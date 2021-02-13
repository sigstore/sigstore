package config

import "github.com/spf13/viper"

type Config struct {
    RSABits            int `mapstructure:"rsa_bits"`
    Email              string `mapstructure:"email"`
    CommonName         string `mapstructure:"common_name"`
	Country            string `mapstructure:"country"`
	Province           string `mapstructure:"province"`
	Locality           string `mapstructure:"locality"`
	Organization       string `mapstructure:"organization"`
	OrganizationalUnit string `mapstructure:"organizationalunit"`
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