#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

int main(int argc, char **argv) {
    int status;
    lua_State *L = luaL_newstate(); luaL_openlibs(L);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s /path/to/a/script.lua\n", argv[0]);
        return 1;
    }

    if (!access(argv[1], F_OK) == 0) {
        fprintf(stderr, "File %s does not exist!\n", argv[1]);
        return 1;
    }

    status = luaL_dofile(L, argv[1]);
    if (status) {
        fprintf(stderr, "Error: %s\n", lua_tostring(L, -1));
        return 1;
    }
    return 0;
}
