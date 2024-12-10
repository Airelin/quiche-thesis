// This app reads concurrently all files from  directory, and 
// Sends them to another peer.
#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::io::Read;
use std::path;
use std::thread;
use std::time::Duration;
use std::fs;

use quiche_apps::args::*;
use quiche_apps::dataclient::*;
use quiche_apps::common::*;

fn main() {

    ////////////////////////////////// Setup Application ////////////////////////////////////////////////////////

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(DATACLIENT_USAGE).unwrap();
    let conn_args = CommonArgs::with_docopt(&docopt);
    let args = DataClientArgs::with_docopt(&docopt);

    // Activate logging to console
    env_logger::builder().format_timestamp_nanos().init();

    ///////////////////////////////// Start one thread per file in directory ////////////////////////////////////
    // Clone string so it does not get moved
    let dir_path =path::PathBuf::from(args.root.clone());

    if let Some(path_str) = dir_path.to_str() {
        if path_str.ends_with('/') {
            // Safe the handles of the threads
            let mut handles= Vec::new();

            // Read the feature header fields from the json file
            let mut content = String::new();
            match std::fs::File::open("./features.json"){
                Ok(mut f) => {
                    if f.read_to_string(&mut content).is_err() {
                        panic!("Panic! Because of an error while reading json to string");
                    }
                },
                Err(e) => panic!("Panic! Because of {}", e)
            };
            let map: HashMap<String, String> = match serde_json::from_str(&content) {
                Ok(map) => map,
                Err(_) => HashMap::new()
            };

            // Get all the files
            let file_paths = fs::read_dir(dir_path).unwrap();
            for file_path in file_paths {
                let handle = match file_path {
                    // Reading the directory worked as expected
                    Ok(f) => {

                        // Clone the arguments to use them
                        let mut arguments = args.clone();
                        let connection_args = conn_args.clone();

                        // Push the features to the request header
                        for key in &map {
                            arguments.req_headers.push(format!("{}: {}", key.0, key.1));
                        }

                        thread::spawn(move|| {
                            let file = f.path();
                            info!("Reading {:?}",file);
                            let body = std::fs::read(file.as_path()).unwrap_or_else(|_| b"Not Found!\r\n".to_vec());
                            arguments.body = Some(body);

                            // Exchange default with actual filename so it can be stored correctly
                            let filename = format!("{:?}", file);
                            let new_url = format!("{}{}",arguments.urls[0].to_string(),&filename[1..(filename.len()-1)]);
                            arguments.urls[0] = url::Url::parse(&new_url).unwrap();

                            // Add user-agent to the headers
                            // quiche::h3::Header::new(b"user-agent", b"quiche"),
                            arguments.req_headers.push(("user-agent: quiche-data").to_string());

                            match connect(arguments, connection_args, stdout_sink) {
                                Err(ClientError::HandshakeFail) => std::process::exit(-1),
                                Err(ClientError::HttpFail) => std::process::exit(-2),
                                Err(ClientError::Other(e)) => panic!("{}", e),                        
                                Ok(_) => info!("Correctly Done!"),
                            }
                            
                            // Surrender so others can run as well
                            thread::sleep(Duration::from_millis(1));
                        })
                    },
                    Err(_) => {
                        thread::spawn(|| {
                        println!("Error while reding the directory");
                        })
                    },
                };
                handles.push(handle);
            }

            ////////////////////////// Catch all the running threads //////////////////////////////////////////////
            info!("{} threads running", handles.len());
            // Wait for all the threads to finish
            for handle in handles{
                handle.join().unwrap();
            }
        }
    }
}