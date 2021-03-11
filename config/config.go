package config

import "github.com/spf13/viper"

type Config struct {
	Email            string `mapstructure:"email"`
}


func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("profiles")
	viper.SetConfigType("toml")
    viper.AutomaticEnv()

    err = viper.ReadInConfig()
    if err != nil {
        return
    }

    err = viper.Unmarshal(&config)
    return
}