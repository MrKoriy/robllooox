#include <stdio.h>
#include <dlfcn.h>

int main() {
    const char* syms[] = {
        "luau_load",
        "luau_compile",
        "lua_pcall",
        "lua_pcallk",
        "lua_tolstring",
        "lua_tostring",
        "lua_getglobal",
        "lua_settop",
        "lua_type",
        "lua_typename",
        "luaL_newstate",
        NULL
    };

    printf("=== Probing dlsym(RTLD_DEFAULT) ===\n");
    for (int i = 0; syms[i]; i++) {
        void* p = dlsym(RTLD_DEFAULT, syms[i]);
        printf("dlsym('%s') = %p\n", syms[i], p);
    }
    return 0;
}
