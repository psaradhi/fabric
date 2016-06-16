/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/hyperledger/fabric/core"
	"github.com/hyperledger/fabric/core/peer"
	pb "github.com/hyperledger/fabric/protos"
)

const chainFuncName = "chaincode"
const undefinedParamValue = ""

const langmsg = "Language the " + chainFuncName + " is written in"
const ctormsg = "Constructor message for the " + chainFuncName + " in JSON format"
const attrmsg = "User attributes for the " + chainFuncName + " in JSON format"
const pathmsg = "Path to " + chainFuncName
const namemsg = "Name of the chaincode returned by the deploy transaction"
const unamemsg = "Username for chaincode operations when security is enabled"

// Chaincode-related variables.
var (
	chaincodeLang           string
	chaincodeCtorJSON       string
	chaincodePath           string
	chaincodeName           string
	chaincodeUsr            string
	chaincodeAttributesJSON string
)

// chaincodeCmd represents the chaincode command
var chaincodeCmd = &cobra.Command{
	Use:   chainFuncName,
	Short: fmt.Sprintf("%s specific commands.", chainFuncName),
	Long:  fmt.Sprintf("%s specific commands.", chainFuncName),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		core.LoggingInit(chainFuncName)
	},
}

func init() {
	RootCmd.AddCommand(chaincodeCmd)

	chaincodeCmd.PersistentFlags().StringVarP(&chaincodeLang, "lang", "l", "golang", langmsg)
	chaincodeCmd.PersistentFlags().StringVarP(&chaincodeCtorJSON, "ctor", "c", "{}", ctormsg)
	chaincodeCmd.PersistentFlags().StringVarP(&chaincodeAttributesJSON, "attributes", "a", "[]", attrmsg)
	chaincodeCmd.PersistentFlags().StringVarP(&chaincodePath, "path", "p", undefinedParamValue, pathmsg)
	chaincodeCmd.PersistentFlags().StringVarP(&chaincodeName, "name", "n", undefinedParamValue, namemsg)
	chaincodeCmd.PersistentFlags().StringVarP(&chaincodeUsr, "username", "u", undefinedParamValue, unamemsg)

}

func getDevopsClient(cmd *cobra.Command) (pb.DevopsClient, error) {
	clientConn, err := peer.NewPeerClientConnection()
	if err != nil {
		return nil, fmt.Errorf("error trying to connect to local peer: %s", err)
	}
	devopsClient := pb.NewDevopsClient(clientConn)
	return devopsClient, nil
}

func checkChaincodeCmdParams(cmd *cobra.Command) (err error) {

	if chaincodeName == undefinedParamValue {
		if chaincodePath == undefinedParamValue {
			err = fmt.Errorf("must supply value for %s path parameter.\n", chainFuncName)
			return
		}
	}

	// Check that non-empty chaincode parameters contain only Function and
	// Args keys. Type checking is done later when the JSON is actually
	// unmarshaled into a pb.ChaincodeInput. To better understand what's going
	// on here with JSON parsing see http://blog.golang.org/json-and-go -
	// Generic JSON with interface{}
	if chaincodeCtorJSON == "{}" {
		err = errors.New("empty JSON chaincode parameters must contain exactly 2 keys - 'Function' and 'Args'")
		return
	}

	var f interface{}
	err = json.Unmarshal([]byte(chaincodeCtorJSON), &f)
	if err != nil {
		err = fmt.Errorf("chaincode argument error: %s", err)
		return
	}
	m := f.(map[string]interface{})
	if len(m) != 2 {
		err = fmt.Errorf("non-empty JSON chaincode parameters must contain exactly 2 keys - 'Function' and 'Args'")
		return
	}
	for k := range m {
		switch strings.ToLower(k) {
		case "function":
		case "args":
		default:
			err = fmt.Errorf("illegal chaincode key '%s' - must be either 'Function' or 'Args'", k)
			return
		}
	}

	if chaincodeAttributesJSON != "[]" {
		var f interface{}
		err = json.Unmarshal([]byte(chaincodeAttributesJSON), &f)
		if err != nil {
			err = fmt.Errorf("chaincode argument error: %s", err)
			return
		}
	}

	return
}

func addSecurityContext(spec *pb.ChaincodeSpec) (err error) {

	privacyEnabled := viper.GetBool("security.privacy")

	//Do few sanity checks reg security & privacy

	if !core.SecurityEnabled() {

		if privacyEnabled {
			panic(errors.New("privacy cannot be enabled as requested because security is disabled"))
		}

		if chaincodeUsr != "" {
			logger.Warning("Username supplied but security is disabled.")
		}

		return
	}

	// Security Enabled
	if chaincodeUsr == "" {
		err = errors.New("must supply username for chaincode when security is enabled")
		return
	}

	logger.Debug("Security is enabled. Include security context in deploy spec")

	// Retrieve the CLI data storage path
	// Returns /var/openchain/production/client/
	localStore := getCliFilePath()

	// Check if the user is logged in before sending transaction
	if _, err = os.Stat(localStore + "loginToken_" + chaincodeUsr); err == nil {
		logger.Infof("Local user '%s' is already logged in. Retrieving login token.\n", chaincodeUsr)

		// Read in the login token
		token, err := ioutil.ReadFile(localStore + "loginToken_" + chaincodeUsr)
		if err != nil {
			panic(fmt.Errorf("fatal error when reading client login token: %s\n", err))
		}

		// Add the login token to the chaincodeSpec
		spec.SecureContext = string(token)

		// If privacy is enabled, mark chaincode as confidential
		if privacyEnabled {
			logger.Info("Set confidentiality level to CONFIDENTIAL.\n")
			spec.ConfidentialityLevel = pb.ConfidentialityLevel_CONFIDENTIAL
		}
	} else {
		// Check if the token is not there and fail
		if os.IsNotExist(err) {
			err = fmt.Errorf("user '%s' not logged in. Use the 'login' command to obtain a security token", chaincodeUsr)
			return
		}
		// Unexpected error
		panic(fmt.Errorf("fatal error when checking for client login token: %s\n", err))
	}

	return nil
}

func createChaincodeSpec(cmd *cobra.Command, args []string) (spec *pb.ChaincodeSpec, err error) {

	if err = checkChaincodeCmdParams(cmd); err != nil {
		return
	}

	// Build the spec
	input := &pb.ChaincodeInput{}
	if err = json.Unmarshal([]byte(chaincodeCtorJSON), &input); err != nil {
		err = fmt.Errorf("chaincode argument error: %s", err)
		return
	}

	var attributes []string
	if err = json.Unmarshal([]byte(chaincodeAttributesJSON), &attributes); err != nil {
		err = fmt.Errorf("chaincode argument error: %s", err)
		return
	}

	chaincodeLang = strings.ToUpper(chaincodeLang)
	spec = &pb.ChaincodeSpec{Type: pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[chaincodeLang]),
		ChaincodeID: &pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName}, CtorMsg: input, Attributes: attributes}

	addSecurityContext(spec)
	return
}
