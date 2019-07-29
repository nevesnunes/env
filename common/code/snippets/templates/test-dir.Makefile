all: txtfile

TARGET_DIR = target-dir

txtfile: $(TARGET_DIR)
	touch $(TARGET_DIR)/file.txt

target-dir:
	test ! -d $(TARGET_DIR) && mkdir $(TARGET_DIR)
