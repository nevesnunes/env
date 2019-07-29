CC = gcc 
CFLAGS = -Wall $(pkg-config --cflags --libs glib-2.0)
EXEC_NAME = testdir 
INCLUDES = 
LIBS =
OBJ_FILES = testdir.o
INSTALL_DIR = /opt/

all : $(EXEC_NAME)
clean :
	rm $(EXEC_NAME) $(OBJ_FILES)

$(EXEC_NAME) : $(OBJ_FILES)
	$(CC) -o $(EXEC_NAME) $(OBJ_FILES) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

install :
	$(shell install -o root -g root $(EXEC_NAME) $(INSTALL_DIR)$(EXEC_NAME))
	$(shell ln -fs $(INSTALL_DIR)$(EXEC_NAME) /etc/cron.hourly)
