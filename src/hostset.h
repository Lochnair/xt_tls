#define MAX_HOST_SET_NAME_LEN 31

struct host_set {
    char name[MAX_HOST_SET_NAME_LEN + 1];
    int refcount;
};//host_set

