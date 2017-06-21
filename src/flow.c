#include <linux/slab.h>

#include "flow.h"

LIST_HEAD(flow_list);

void flow_add(flow_data * flow)
{
	INIT_LIST_HEAD(&flow->list);
	list_add(&flow->list, &flow_list);
}

void flow_destroy(void)
{
	flow_data * flow;
	struct list_head * pos;
	list_for_each_prev(pos, &flow_list) {
		flow = list_entry(pos, flow_data, list);
		list_del(&flow->list);
		kfree(flow->data);
		kfree(flow);
	}
}

flow_data * flow_get(__u32 hash)
{
	flow_data * flow;
	struct list_head * pos;
	list_for_each(pos, &flow_list) {
		flow = list_entry(pos, flow_data, list);
		if (flow->hash == hash)
			return flow;
	}

	return NULL;
}

void flow_remove(__u32 hash)
{
	flow_data * flow = flow_get(hash);
	WARN_ON(flow == NULL);

	list_del(&flow->list);
	kfree(flow->data);
	kfree(flow);
}
