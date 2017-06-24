typedef struct {
	u32 hash;
	u8 *data;
	u16 data_len;
	u8 *tail;
	struct list_head list;
} flow_data;

void flow_add(flow_data * flow);

void flow_destroy(void);

flow_data * flow_get(u32 hash);

void flow_remove(u32 hash);
