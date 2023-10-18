import json

class Store():
    
    def add_item(item):
        with open('almacen.json', "r", encoding="utf-8", newline="") as file:
            _data_list = json.load(file)
        file.write('Hola')
        file.close()