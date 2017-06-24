typedef struct {
	__u32 hash;
	__u8 *data;
	__u16 data_len;
	__u8 *tail;
	struct list_head list;
} flow_data;

void flow_add(flow_data * flow);

void flow_destroy(void);

flow_data * flow_get(__u32 hash);

void flow_remove(__u32 hash);
