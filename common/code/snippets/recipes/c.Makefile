FLAGS += -MMD
CFLAGS += $(FLAGS)
CXXFLAGS += $(FLAGS)

OBJECTS += $(patsubst %, build/%.o, $(SOURCES))
DEPS = $(patsubst %, build/%.d, $(SOURCES))

$(TARGET): $(OBJECTS)
	$(CXX) -o $@ $^ $(LDFLAGS)

-include $(DEPS)

build/%.c.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

build/%.cpp.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c -o $@ $<
