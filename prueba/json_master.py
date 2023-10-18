"json_store_master"
import json

class JsonStoreMaster():
    """beginning of class"""
    _FILE_PATH = ""
    _ID_FIELD = ""
    _data_list = []
    __ERROR_MESSAGE = "Wrong file or file path"
    __ERROR_JSON_DECODE = "JSON Decode Error - Wrong JSON Format"
    def __init__(self):
        self.load_store()

    def load_store(self):
        with open(self._FILE_PATH, "r", encoding="utf-8", newline="") as file:
            self._data_list = json.load(file)

    def save_store(self):
        with open(self._FILE_PATH, "w", encoding="utf-8", newline="") as file:
            json.dump(self._data_list, file, indent=2)

    def find_data(self, data_to_find):
        item_found = None
        for item in self._data_list:
            if item[self._ID_FIELD] == data_to_find:
                item_found = item
        return item_found

    def add_item(self, item):
        """add item to the store"""
        self.load_store()
        self._data_list.append(item.__dict__)
        self.save_store()
