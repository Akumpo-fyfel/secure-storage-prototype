# secure-storage-prototype  

    git clone https://github.com/Akumpo-fyfel/secure-storage-prototype.git   
    cd secure-storage-prototype   
    python -m venv venv   
    .\venv\Scripts\Activate.ps1   
    pip install -r requirements.txt    
 

# Инициализация БД    
    cd secure-storage-prototype   
    python scripts\scripts_init_db.py   
    python scripts\scripts_init_access_db.py   
    python scripts\scripts_init_files_db.py   
    python scripts\scripts_init_audit_db.py 


# Доверенное состояние (при изменениях в модулях запустить повторно)   
    python trust\init_trust.py   

# Запуск    
    python trust\secure_start.py   

# Учетная запись по умолчанию    
    admin / admin    

Для raspberry требуется драйвер, если нет, то https://github.com/raspberrypi/rpi-usb-gadget/releases/tag/v1.0.6  
на raspberry:   
              
              sudo apt update   
              sudo apt install rpi-usb-gadget   
              sudo rpi-usb-gadget on   
              sudo reboot   
              
              sudo apt install git -y   
              sudo apt install python3-venv -y     
              git clone https://github.com/Akumpo-fyfel/secure-storage-prototype.git    
              cd secure-storage-prototype    
              python3 -m venv venv   
              source venv/bin/activate   
              pip install -r requirements.txt   

              .gitkeep почему-то не сработал, надо создать папки
              mkdir -p service
              mkdir -p service/encrypted_master_keys

              mkdir -p storage
              mkdir -p storage/encrypted_files
              mkdir -p storage/encrypted_file_keys
              mkdir -p storage/encrypted_metadata

              mkdir -p rotation_backups

              создание файлов xxx.db
              python scripts\scripts_init_db.py   
              python scripts\scripts_init_db.py  
              python scripts\scripts_init_access_db.py   
              python scripts\scripts_init_files_db.py   
              python scripts\scripts_init_audit_db.py   
              
              python trust\init_trust.py  
              python trust\secure_start.py

              ip addr:   usb0: inet x.x.x.x ---> http://x.x.x.x:5000

              
              
              
