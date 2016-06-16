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
	"fmt"

	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

// invokeCmd represents the invoke command
var invokeCmd = &cobra.Command{
	Use:       "invoke",
	Short:     fmt.Sprintf("Invoke the specified %s.", chainFuncName),
	Long:      fmt.Sprintf(`Invoke the specified %s.`, chainFuncName),
	ValidArgs: []string{"1"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return chaincodeInvoke(cmd, args)
	},
}

func init() {
	chaincodeCmd.AddCommand(invokeCmd)

	// Here you will define your flags and configuration settings.
}

// chaincodeInvoke invokes the chaincode. If successful, the
// INVOKE form prints the transaction ID on STDOUT.
func chaincodeInvoke(cmd *cobra.Command, args []string) (err error) {

	spec, err := createChaincodeSpec(cmd, args)
	if err != nil {
		err = fmt.Errorf("error invoking %s: %s\n", chainFuncName, err)
		return
	}

	// Build the ChaincodeInvocationSpec message
	invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

	devopsClient, err := getDevopsClient(cmd)
	if err != nil {
		err = fmt.Errorf("error building %s: %s", chainFuncName, err)
		return
	}

	resp, err := devopsClient.Invoke(context.Background(), invocation)
	if err != nil {
		err = fmt.Errorf("error invoking %s: %s\n", chainFuncName, err)
		return
	}

	transactionID := string(resp.Msg)
	logger.Info("Successfully invoked transaction: %s(%s)", invocation, transactionID)
	fmt.Println(transactionID)
	return nil
}
