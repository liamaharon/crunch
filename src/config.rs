use metre::{Config, ConfigLoader, Format};


#[derive(Config, Debug)]
pub struct AppConfig {
    #[config(default= "mirror".to_string())]
    pub remote_path: String,

    #[config(default = 30)]
    pub timeout_secs: u64,

    #[config(default = false)]
    pub verbose: bool,

    #[config(default = "target,.git".to_string())]
    pub exclude: String,

    #[config(default = "RUST_BACKTRACE=1".to_string())]
    pub build_env: String,
}


impl AppConfig {
    pub fn load_config() -> Result<Self, metre::Error> {
        let mut loader = ConfigLoader::<AppConfig>::new();
        loader.defaults()?;

       if let Some(home) = dirs::home_dir() {
           let cfg_path = home.join(".config").join("crunch.toml");
           if cfg_path.exists() {
               if let Some(path_str) = cfg_path.to_str() {
                   loader.file(path_str, Format::Toml)?;
               } else {
                   eprint!("Path is not valid UTF-8: {:?}", cfg_path);
               }
           } else {
               eprint!("Config file not found: {}", cfg_path.display());
           }
       }

       // Load from project-specific config if it exists
       if let Ok(manifest) = std::env::current_dir() {
           let project_cfg = manifest.join("crunch.toml");
           if project_cfg.exists() {
               if let Some(path_str) = project_cfg.to_str() {
                   loader.file(path_str, Format::Toml)?;
               }
           }
       }
       loader.env()?;

       loader.finish()
   } 
}
