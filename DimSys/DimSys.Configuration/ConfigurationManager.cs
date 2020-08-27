using System;
using Microsoft.Extensions.Configuration;

namespace DimSys.Configuration {
    public class ConfigurationManager {

        public IConfiguration Configuration { get; }

        public ConfigurationManager(IConfiguration config) {

            if (config is null) {
                throw new Exception("Configuration object must be set");
            }

            Configuration = config;
        }

        public IConfigurationSection GetSection(string sectionName) {
            return Configuration.GetSection(sectionName);
        }

        public string GetConfig(string configName, string sectionName = "", bool nullAsEmpty = true) {
            string s = null;
            try {
                if (sectionName != "") {
                    IConfigurationSection section = GetSection(sectionName);
                    if (!(section is null)) {
                        s = section.GetValue<string>(configName);
                    }
                }
                else {
                    s = Configuration.GetValue<string>(configName);
                }
            }
            catch {}

            if (s == null && nullAsEmpty)
                s = "";
            return s;
        }
    }
}
