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
	"errors"
	"fmt"

	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

var chaincodeQueryRaw, chaincodeQueryHex bool

// queryCmd represents the query command
var queryCmd = &cobra.Command{
	Use:       "query",
	Short:     "Query using the specified chaincode.",
	Long:      "Query using the specified chaincode.",
	ValidArgs: []string{"1"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return chaincodeQuery(cmd, args)
	},
}

func init() {
	chaincodeCmd.AddCommand(queryCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// queryCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// queryCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rawmsg := "If true, output the query value as raw bytes, otherwise format as a printable string"
	queryCmd.Flags().BoolVarP(&chaincodeQueryRaw, "raw", "r", false, rawmsg)

	hexmsg := "If true, output the query value byte array in hexadecimal. Incompatible with --raw"
	queryCmd.Flags().BoolVarP(&chaincodeQueryHex, "hex", "x", false, hexmsg)

}

// chaincodeQuery queries the chaincode. If successful,
// the query result is printed on STDOUT. A command-line flag (-r, --raw) determines
// whether the query result is output as raw bytes, or as a printable string.
// The printable form is optionally (-x, --hex) a hexadecimal representation
// of the query response. If the query response is NIL, nothing is output.
func chaincodeQuery(cmd *cobra.Command, args []string) (err error) {

	if chaincodeQueryRaw && chaincodeQueryHex {
		err = errors.New("options --raw (-r) and --hex (-x) are not compatible\n")
		return
	}

	spec, err := createChaincodeSpec(cmd, args)
	if err != nil {
		err = fmt.Errorf("error querying %s: %s\n", chainFuncName, err)
		return
	}

	// Build the ChaincodeInvocationSpec message
	invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

	devopsClient, err := getDevopsClient(cmd)
	if err != nil {
		err = fmt.Errorf("error building %s: %s", chainFuncName, err)
		return
	}

	resp, err := devopsClient.Query(context.Background(), invocation)

	if err != nil {
		err = fmt.Errorf("error querying %s: %s\n", chainFuncName, err)
		return
	}

	logger.Infof("Successfully queried transaction: %s", invocation)
	if resp != nil {
		if chaincodeQueryHex {
			fmt.Printf("%x\n", resp.Msg)
		} else {
			fmt.Println(string(resp.Msg))
		}
	}
	return nil
}
