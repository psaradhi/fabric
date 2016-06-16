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

//Package cmd contains all commands for peer
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hyperledger/fabric/core"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/op/go-logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var logger = logging.MustGetLogger("main")

const cmdRoot = "core"

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use: "peer",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        viper.Debug()
	// Init the crypto layer
	if err := crypto.Init(); err != nil {
		panic(fmt.Errorf("failed to initialize the crypto layer: %s", err))
	}
		return core.CacheConfiguration()
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $GOPATH/src/github.com/hyperledger/fabric/peer/core.yaml)")

	// Define command-line flags that are valid for all peer commands and subcommands.
	mainFlags := RootCmd.PersistentFlags()
	mainFlags.String("logging-level", "", "Default logging level and overrides, see core.yaml for full syntax")
	viper.BindPFlag("logging_level", mainFlags.Lookup("logging-level"))

	runtime.GOMAXPROCS(viper.GetInt("peer.gomaxprocs"))
}

// Sets configuration file (can be passed from command line) and all dirs to search based on GOPATH
func setConfigFile() {

	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
		return
	}

	viper.SetConfigName(cmdRoot) // name of config file (without extension)

	// Path to look for the config file in based on GOPATH
	gopath := os.Getenv("GOPATH")
	for _, p := range filepath.SplitList(gopath) {
		peerpath := filepath.Join(p, "src/github.com/hyperledger/fabric/peer")
		viper.AddConfigPath(peerpath)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {

	setConfigFile()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		logger.Infof("using config file: [%s]", viper.ConfigFileUsed())
	} else {
		panic(fmt.Errorf("fatal error when reading %s config file: %s\n", cmdRoot, err))
	}

	viper.SetEnvPrefix(cmdRoot)
	viper.AutomaticEnv() // read in environment variables that match
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

}
