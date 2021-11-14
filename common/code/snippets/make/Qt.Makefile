# Based on:
# - https://www.partow.net/programming/makefile/index.html
# - https://doc.qt.io/qt-5/moc.html
# - https://gist.github.com/mishurov/8134532

CXX      := -c++
MOC      := moc
UIC      := uic
CXXFLAGS := -fPIC
LDFLAGS  := -L/usr/lib/x86_64-linux-gnu -lQt5Quick  -lQt5PrintSupport -lQt5Qml -lQt5Network -lQt5Widgets -lQt5Gui -lQt5Core
BUILD    := ./build
OBJ_DIR  := $(BUILD)/objects
APP_DIR  := $(BUILD)/apps
INC_DIR  := $(BUILD)/include
MOC_DIR  := $(BUILD)/moc
TARGET   := realtimeplot
INCLUDE  := 			\
	-Iinclude/ \
	-I$(INC_DIR) \
	-Iinclude/qcustomplot \
	-I/usr/include/x86_64-linux-gnu/qt5 \
	-I/usr/include/x86_64-linux-gnu/qt5/QtWidgets \
	-I/usr/include/x86_64-linux-gnu/qt5/QtCore \
	-I/usr/include/x86_64-linux-gnu/qt5/QtGui \

SRC      :=                      \
	$(wildcard src/qcustomplot/*.cpp) \
	$(wildcard src/*.cpp)         \

OBJECTS  := $(SRC:%.cpp=$(OBJ_DIR)/%.o)

all: build $(APP_DIR)/$(TARGET)

# mrv: generate ui_mainwindow.h
$(INC_DIR)/ui_mainwindow.h: src/mainwindow.ui
	$(UIC) $< -o $@

# mrv: compile all cpp source files
$(OBJ_DIR)/%.o: %.cpp $(INC_DIR)/ui_mainwindow.h
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $@ -c $<

# mrv: process moc header with Qt's moc utility
# (Qt's signal/slot functionality requires generation of some extra code)
$(MOC_DIR)/moc_mainwindow.cpp: include/mainwindow.h
	$(MOC) $(INCLUDE) $< -o $@

# mrv: process moc header with Qt's moc utility
# (Qt's signal/slot functionality requires generation of some extra code)
$(MOC_DIR)/moc_qcustomplot.cpp: include/qcustomplot/qcustomplot.h
	$(MOC) $(INCLUDE) $< -o $@

# mrv: compile the output of Qt's moc utility
$(OBJ_DIR)/src/moc_mainwindow.o: $(MOC_DIR)/moc_mainwindow.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $@ -c $<

# mrv: compile the output of Qt's moc utility
$(OBJ_DIR)/src/moc_qcustomplot.o: $(MOC_DIR)/moc_qcustomplot.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $@ -c $<

# mrv: the order in which the libraries are linked is important!
# mrv: linking libraries must follow the executable and not precede it
$(APP_DIR)/$(TARGET): $(OBJ_DIR)/src/moc_mainwindow.o $(OBJ_DIR)/src/moc_qcustomplot.o $(OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) $^ -o $@ $(LDFLAGS)

.PHONY: all build clean debug release

build:
	@mkdir -p $(APP_DIR)
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(INC_DIR)
	@mkdir -p $(MOC_DIR)

debug: CXXFLAGS += -DDEBUG -g
debug: all

release: CXXFLAGS += -O2
release: all

clean:
	-@rm -rvf $(OBJ_DIR)/*
	-@rm -rvf $(APP_DIR)/*
	-@rm -rvf $(INC_DIR)/*
	-@rm -rvf $(MOC_DIR)/*
