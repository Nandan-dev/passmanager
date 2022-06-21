use eframe::App;
use egui::CentralPanel;
use serde_json::json;

use serde::{Serialize , Deserialize};

use egui_extras::{TableBuilder , Size};

use aes_gcm_siv::{Key, Aes256GcmSiv, Nonce};
use aes_gcm_siv::aead::NewAead;
use aes_gcm_siv::aead::Aead;
use blake2b_simd::Params;

use std::fs;
use std::fs::{File, read_to_string};
use std::io::{Bytes, Write, BufReader, BufRead, BufWriter, Read, };
use std::error::Error;
use std::collections::HashSet;

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native("passmanager", options, Box::new(|_cc| Box::new(Theapp::default())));
}

#[derive(Serialize , Deserialize, PartialEq)]
struct dbfile {
    dbname: String ,
    passwordlist: Vec<passowrds>
}

#[derive(Serialize , Deserialize, PartialEq , Debug)]
struct passowrds {
    id: String,
    username: String,
    password: String
}

#[derive(PartialEq)]
enum displaypage {
    homepage,
    newdbpage,
    passwordspage,
    editpage
}

struct Theapp {
    displaytab: displaypage,
    passdbname: String,
    passdblocation: Option<String>,
    password : String,
    hidepass : bool,
    openpassdblocation: Option<String>,
    hidedbpasswords: bool,
    selectedpass : Option<u64>,
    passdb: Vec<passowrds>,
    editmode : bool,
    newpass: bool,
}

impl Theapp {
    fn addnewpassword(&mut self) {
        self.passdb.push(passowrds { id: String::from(""), username: String::from(""), password: String::from("") });
    }

    fn savefile(&mut self) {
        let mut passdbname = &self.passdbname;
        let mut db = &self.passdb;
        let mut location = self.openpassdblocation.as_ref().unwrap().trim();
        // let passdb  = refdbfile {
        //     dbname: passdbname.to_string(),
        //     passwordlist: db,
        // };

        let mut passdb  = json!({
            "dbname": passdbname.to_string(),
            "passwordlist": db
        }); 

        println!("{}" , location);

        let jsonfile = match read_to_string("./config.json") {
            Ok(T) => T,
            Err(e) => "
                {
                    \"aes256gcmsiv\" : {
                        \"personal\" : \"1$TEl5WXdiaHBCM\",
                        \"salt\" : \"mxjZURQVA$IU3Srw\",
                        \"nonceslice\" : \"GS2x3Yw$5ZXP\"
                    }
                }
            ".to_string(),
        };

        let jsoncontents: serde_json::Value = serde_json::from_str(jsonfile.as_str()).unwrap();
        let settings = jsoncontents.get("aes256gcmsiv").unwrap();


        let mut hash = Params::new().hash_length(16).key(self.password.as_bytes()).personal(settings.get("personal").unwrap().as_str().unwrap().as_bytes()).salt(settings.get("salt").unwrap().as_str().unwrap().as_bytes()).to_state();
        let res = hash.finalize().to_hex();


        let key = Key::from_slice(res.as_bytes());
        let cipher = Aes256GcmSiv::new(key);

        let mut fileloc = File::create(location).unwrap();
        // let mut filecontents = Vec::new();
        // let mut file = File::open(infile.trim()).unwrap();
        // file.read_to_end(&mut filecontents).unwrap();

        let ciphertext = cipher.encrypt(Nonce::from_slice(settings.get("nonceslice").unwrap().as_str().unwrap().as_bytes()), passdb.to_string().as_bytes()).expect("ERROR WHILE ENCRYPTING AES 256 BIT GCM SIV");

        for i in &ciphertext {
            write!(fileloc , "{}", *i as char);
        }

        // let mut file = File::create(location).unwrap();
        // file.write(passdb.to_string().as_bytes());


    }

    fn openfile(&mut self) {
        
        let jsonfile = match read_to_string("./config.json") {
            Ok(T) => T,
            Err(e) => "
                {
                    \"aes256gcmsiv\" : {
                        \"personal\" : \"1$TEl5WXdiaHBCM\",
                        \"salt\" : \"mxjZURQVA$IU3Srw\",
                        \"nonceslice\" : \"GS2x3Yw$5ZXP\"
                    }
                }
            ".to_string(),
        };

        let jsoncontents: serde_json::Value = serde_json::from_str(&jsonfile.as_str()).unwrap();
        let settings = jsoncontents.get("aes256gcmsiv").unwrap();

        let mut hash = Params::new().hash_length(16).key(self.password.as_bytes()).personal(settings.get("personal").unwrap().as_str().unwrap().as_bytes()).salt(settings.get("salt").unwrap().as_str().unwrap().as_bytes()).to_state();
        let res = hash.finalize().to_hex();

        let key = Key::from_slice(res.as_bytes());
        let cipher = Aes256GcmSiv::new(key);;

        let mut encrypted: Vec<u8> = Vec::new();
        let encryptedfile = read_to_string(self.openpassdblocation.as_ref().unwrap().trim()).unwrap();

        for i in encryptedfile.chars() {
            encrypted.push(i as u8);
        }

        let decipheredtext = cipher.decrypt(Nonce::from_slice(settings.get("nonceslice").unwrap().as_str().unwrap().as_bytes()), encrypted.as_ref()).unwrap();

        let mut decryptedtext: Vec<u8> = Vec::new();

        for i in decipheredtext.bytes() {
            decryptedtext.push(i.unwrap());
        }


        let file = String::from_utf8(decryptedtext).unwrap();
        println!("{:#?}" , &file);
        let mut contents: dbfile  = serde_json::from_str(file.as_str()).unwrap();
        let mut passwordslistvec: Vec<passowrds> = contents.passwordlist;
        println!("{:#?}",&passwordslistvec);
        self.passdb = passwordslistvec; 
    }

    fn createdb(&mut self) {
        let name: &String = &self.passdbname;
        let mut contents = json!({
            "dbname" : name,
            "passwordlist" : [
                {
                    "id" : "demo",
                    "username" : "username",
                    "password" : "password"
                }
            ]
        });

        let jsonfile = match read_to_string("./config.json") {
            Ok(T) => T,
            Err(e) => "
                {
                    \"aes256gcmsiv\" : {
                        \"personal\" : \"1$TEl5WXdiaHBCM\",
                        \"salt\" : \"mxjZURQVA$IU3Srw\",
                        \"nonceslice\" : \"GS2x3Yw$5ZXP\"
                    }
                }
            ".to_string(),
        };

        let jsoncontents: serde_json::Value = serde_json::from_str(jsonfile.as_str()).unwrap();
        let settings = jsoncontents.get("aes256gcmsiv").unwrap();


        let mut hash = Params::new().hash_length(16).key(self.password.as_bytes()).personal(settings.get("personal").unwrap().as_str().unwrap().as_bytes()).salt(settings.get("salt").unwrap().as_str().unwrap().as_bytes()).to_state();
        let res = hash.finalize().to_hex();


        let key = Key::from_slice(res.as_bytes());
        let cipher = Aes256GcmSiv::new(key);

        let mut fileloc = File::create(self.passdblocation.as_ref().unwrap()).unwrap();
        // let mut filecontents = Vec::new();
        // let mut file = File::open(infile.trim()).unwrap();
        // file.read_to_end(&mut filecontents).unwrap();

        let ciphertext = cipher.encrypt(Nonce::from_slice(settings.get("nonceslice").unwrap().as_str().unwrap().as_bytes()), contents.to_string().as_bytes()).expect("ERROR WHILE ENCRYPTING AES 256 BIT GCM SIV");

        for i in &ciphertext {
            write!(fileloc , "{}", *i as char);
        }
    }
}

impl Default for Theapp {
    fn default() -> Self {
        Self{
            displaytab : displaypage::homepage,
            passdbname : String::from("passwordlist"),
            passdblocation : Some(String::from("Select password location")),
            password : String::from("password"),
            hidepass : true,
            openpassdblocation: Some(String::from("select password db location")),
            hidedbpasswords: false,
            selectedpass: None,
            passdb: Vec::new(),
            editmode: false,
            newpass: false,
        }
    }
    
}

impl App for Theapp {
    
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {



        egui::CentralPanel::default().show(ctx, |ui|{

            
            egui::TopBottomPanel::top("topmenubar").show(ctx, |ui| {
                ui.horizontal(|ui|{
                    ui.spacing();
                    ui.heading("Pass Manager 🔐");
                    egui::global_dark_light_mode_buttons(ui);
                });
            });
            match &self.displaytab {
                displaypage::homepage => {
                    // if ui.button("Create new password databse").clicked() {
                    //     self.displaytab =  displaypage::newdbpage;
                    // }
                    // if ui.button(" password databse").clicked() {
                    //     self.displaytab =  displaypage::passwordspage;
                    // }
                    // if ui.button("Open existing file").clicked() {
                    //     if let Some(path) = rfd::FileDialog::new().pick_file() {
                    //         self.openpassdblocation = Some(path.display().to_string());
                    //         // self.passdb = getpasswords(self.openpassdblocation.as_ref().unwrap() , self.password.clone());
                    //         self.openfile();
                    //     }
                    //      self.displaytab =  displaypage::passwordspage;
                    // }
                    
                    CentralPanel::default().show(ctx, |ui| {
                        ui.centered_and_justified(|ui| {
                            ui.vertical(|ui|{
                                ui.horizontal(|ui| {
                                    ui.add(egui::TextEdit::singleline(&mut self.password).password(self.hidepass));
    
                                    ui.checkbox(&mut self.hidepass, "Hide password : ");
                                });
    
                                ui.horizontal(|ui|{
                                    if ui.button("Create new password databse").clicked() {
                                        self.displaytab =  displaypage::newdbpage;
                                    }
                                    if ui.button("Open existing file").clicked() {
                                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                                            self.openpassdblocation = Some(path.display().to_string());
                                            // self.passdb = getpasswords(self.openpassdblocation.as_ref().unwrap() , self.password.clone());
                                            self.openfile();
                                        }
                                         self.displaytab =  displaypage::passwordspage;
                                    }
                                });
                            });
                        });
                    });

                }


                    
                displaypage::newdbpage => {
                    CentralPanel::default().show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.monospace("Enter Password : ");

                           ui.add(egui::TextEdit::singleline(&mut self.password).password(self.hidepass));

                            ui.checkbox(&mut self.hidepass, "Hide password : ");

                        });


                        ui.horizontal(|ui|{
                            ui.label("Enter Name : ");
                            ui.text_edit_singleline(&mut self.passdbname);
                        });
                        ui.horizontal(|ui| {
                            if ui.button("Select location ").clicked() {
                                if let Some(path) = rfd::FileDialog::new().save_file() {
                                    self.passdblocation = Some(path.display().to_string())
                                }
                            }
                            ui.label(format!("file location -> {}" , self.passdblocation.as_ref().unwrap()));
                        });
                        if ui.button("Save File").clicked() {
                            self.createdb();
                            // createdb(&self.passdblocation , &self.password, &self.passdbname);
                        }
                    });
                },
                displaypage::passwordspage => {
                    CentralPanel::default().show(ctx, |ui| {
                        ui.horizontal(|ui|{
                            ui.monospace(format!("password db location -> {}" , self.openpassdblocation.as_ref().unwrap()));
                            ui.heading("text")
                        });
                        TableBuilder::new(ui)
                            .column(Size::relative(0.30))
                            .column(Size::relative(0.30))
                            .column(Size::relative(0.30))
                            .column(Size::relative(0.10))
                            .striped(true)
                            .header(20.0, |mut header| {
                                header.col(|ui| {
                                    ui.heading("Password ID");
                                });
                                header.col(|ui| {
                                    ui.heading("Username");
                                });
                                header.col(|ui| {
                                    // ui.heading("Password");
                                    ui.checkbox(&mut self.hidedbpasswords, "Show Passwords");
                                });
                            })
                            .body(|mut body| {
                                for mut i  in  &mut self.passdb {
                                    body.row(30.0, |mut row| {
                                        row.col(|ui| {
                                            if &self.editmode == &true {
                                                ui.text_edit_singleline(&mut i.id);
                                            } else {
                                                ui.monospace(&i.id);
                                            }
                                        });
                                        row.col(|ui| {
                                            if &self.editmode == &true {
                                                ui.text_edit_singleline(&mut i.username);
                                            } else {
                                                ui.monospace(&i.username);
                                            }
                                        });
                                        row.col(|ui| {
                                            ui.set_visible(self.hidedbpasswords);
                                            if &self.editmode == &true {
                                                ui.text_edit_singleline(&mut i.password);
                                            } else {
                                                ui.monospace(&i.password);
                                            }
                                        });
                                        row.col(|ui| {
                                            ui.menu_button("More Options", |ui| {
                                                if ui.button("New Entry").clicked() {
                                                    ui.close_menu();
                                                }
                                                if ui.button("Edit Entry").clicked() {
                                                    if self.editmode == true {
                                                        self.editmode = false;
                                                    } else {
                                                        self.editmode = true;
                                                    }
                                                    ui.close_menu();
                                                }
                                                if ui.button("New entry").clicked() {
                                                    self.newpass = true;
                                                    
                                                    self.editmode = true;
                                                    ui.close_menu();
                                                }
                                            });
                                        });
                                    });

                                    
                                }
                            });

                            ui.horizontal(|ui| {
                                if ui.button("Save File").clicked() {
                                    self.savefile();
                                }
    
                                if ui.button("New Entry").clicked() {
                                    self.newpass = true;
                                }
                            });

                            if &self.newpass == &true {
                                self.addnewpassword();
                            }
                            self.newpass = false;
                        

                            // if self.displaytab == displaypage::editpage {
                            //     ui.monospace("text");
                            // }

                            

                    });
                },
                   displaypage::editpage => {
                       CentralPanel::default().show(ctx, |ui| {
                           ui.monospace("sdasd");
                       });
                   } 
            }
        });
    }
}

fn createdb(filelocation: &Option<String> , password :  &String , name : &String) {
    let mut contents = json!({
        "dbname" : name,
        "passwordlist" : {}
    });


    let mut fileloc = File::create(filelocation.as_ref().unwrap().trim()).unwrap();
    fileloc.write_all(contents.clone().to_string().as_bytes());
}

fn getpasswords(fileloc: &String, password :  &String) -> Vec<passowrds> {

    let jsonfile = match read_to_string("./config.json") {
        Ok(T) => T,
        Err(e) => "
            {
                \"aes256gcmsiv\" : {
                    \"personal\" : \"1$TEl5WXdiaHBCM\",
                    \"salt\" : \"mxjZURQVA$IU3Srw\",
                    \"nonceslice\" : \"GS2x3Yw$5ZXP\"
                }
            }
        ".to_string(),
    };

    let jsoncontents: serde_json::Value = serde_json::from_str(&jsonfile.as_str()).unwrap();
    let settings = jsoncontents.get("aes256gcmsiv").unwrap();

    let mut hash = Params::new().hash_length(16).key(password.as_bytes()).personal(settings.get("personal").unwrap().as_str().unwrap().as_bytes()).salt(settings.get("salt").unwrap().as_str().unwrap().as_bytes()).to_state();
    let res = hash.finalize().to_hex();

    let key = Key::from_slice(res.as_bytes());
    let cipher = Aes256GcmSiv::new(key);;

    let mut encrypted: Vec<u8> = Vec::new();
    let encryptedfile = read_to_string(fileloc.trim()).unwrap();

    for i in encryptedfile.chars() {
        encrypted.push(i as u8);
    }

    let decipheredtext = cipher.decrypt(Nonce::from_slice(settings.get("nonceslice").unwrap().as_str().unwrap().as_bytes()), encrypted.as_ref()).unwrap();

    let mut decryptedtext: Vec<u8> = Vec::new();

    for i in decipheredtext.bytes() {
        decryptedtext.push(i.unwrap());
    }


    let file = String::from_utf8(decryptedtext).unwrap();
    println!("{:#?}" , &file);
    let mut contents: dbfile  = serde_json::from_str(file.as_str()).unwrap();
    let mut passwordslistvec: Vec<passowrds> = contents.passwordlist;
    passwordslistvec
}

