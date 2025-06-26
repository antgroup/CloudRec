// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"github.com/core-sdk/log"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

// LoadConfig load config file
func LoadConfig() (error, Options) {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")      // optionally look for config in the working directory
	err := viper.ReadInConfig()   // Find and read the config file
	if err = viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.GetWLogger().Warn(fmt.Sprintf("config file not found %s", err.Error()))
		} else {
			log.GetWLogger().Warn(fmt.Sprintf("%s", err.Error()))
		}
	}

	hostname, _ := os.Hostname()
	// init opt
	opt := Options{
		AgentName:   hostname,
		RunOnlyOnce: true,
		Cron:        defaultCron,
		ServerUrl:   defaultServerUrl,
	}
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		err := viper.Unmarshal(&opt)
		if err != nil {
			panic(fmt.Errorf("config file changed but find err:%v", err))
		}
	})

	if err1 := viper.Unmarshal(&opt); err1 != nil {
		panic(fmt.Errorf("unmarshal data to Conf failed,err:%v", err))
	}

	// ==================  accessToken Supports reading from the command line, with the highest priority ==================
	var accessToken string
	var serverUrl string
	var rootCmd = &cobra.Command{
		Use:   "app",
		Short: "An example app with Cobra",
		Run: func(cmd *cobra.Command, args []string) {
			if accessToken != "" {
				log.GetWLogger().Info(fmt.Sprintf("read arguments [accessToken]:[%s] from the command line", accessToken))
				opt.AccessToken = accessToken
			}
			if serverUrl != "" {
				log.GetWLogger().Info(fmt.Sprintf("read arguments [serverUrl]:[%s] from the command line", serverUrl))
				opt.ServerUrl = serverUrl
			}
		},
	}

	rootCmd.Flags().StringVar(&accessToken, "accessToken", "", "accessToken from console")
	rootCmd.Flags().StringVar(&serverUrl, "serverUrl", "", "serverUrl from console")
	if err := rootCmd.Execute(); err != nil {
		log.GetWLogger().Error(fmt.Sprintf("read arguments from the command line err %s", err.Error()))
	}

	// ==================  AttentionErrorTexts deduplication ==================
	if len(opt.AttentionErrorTexts) > 0 {
		seen := make(map[string]struct{})
		result := make([]string, 0, len(opt.AttentionErrorTexts))
		for _, text := range opt.AttentionErrorTexts {
			if _, exists := seen[text]; !exists {
				seen[text] = struct{}{}
				result = append(result, text)
			}
		}
		opt.AttentionErrorTexts = result
	}

	return nil, opt
}
