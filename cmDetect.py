#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse


bpf_text = """
    #include <linux/sched.h>
    #include <linux/fs.h>

    #define MAX_ARG_STR_LEN 64
    #define MAX_TOTAL_ARGS 5
    #define MAX_ARGS_ARR (MAX_TOTAL_ARGS * MAX_ARG_STR_LEN)
    #define LAST_ARG_POS (MAX_ARGS_ARR - MAX_ARG_STR_LEN)

    struct data_t {
        u32 uid;
        u32 pid;
        u32 ppid;
        char comm[TASK_COMM_LEN];
        int retval;
        unsigned int args_size;
        char argv[MAX_ARGS_ARR];
    };

    BPF_PERF_OUTPUT(events);
    BPF_HASH(tasks, u32, struct data_t);

    static int __bpf_read_arg_str(struct data_t *data, const char *ptr)
    {
        if (data->args_size > LAST_ARG_POS) {
            return -1;
        }

        int ret = bpf_probe_read_user_str(&data->argv[data->args_size], MAX_ARG_STR_LEN,
                                        (void *)ptr);
        if (ret > MAX_ARG_STR_LEN || ret < 0) {
            return -1;
        }

        data->args_size += (ret - 1);

        return 0;
    }

    static int __bpf_read_arg(struct data_t *data, const char *ptr, int size)
    {
        if (data->args_size > LAST_ARG_POS) {
            return -1;
        }

        int ret =
            bpf_probe_read(&data->argv[data->args_size], MAX_ARG_STR_LEN, (void *)ptr);
        if (ret < 0) {
            return -1;
        }

        data->args_size += size;
        return 0;
    }

    TRACEPOINT_PROBE(syscalls, sys_enter_execve)
    {

        const char spaces[] = " ";
        const char ellipsis[] = "...";
        unsigned int ret = 0;

        const char **argv = (const char **)(args->argv);

        struct data_t data = {};

        u32 pid = bpf_get_current_pid_tgid();
        data.pid = pid;
        data.uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        data.ppid = task->real_parent->tgid;

        if (__bpf_read_arg_str(&data, (const char *)argv[0]) < 0) {
            goto out;
        }

        if (__bpf_read_arg(&data, (const char *)spaces, 1) < 0) {
            goto out;
        }

    #pragma unroll
        for (int i = 1; i < MAX_TOTAL_ARGS; i++) {
            if (__bpf_read_arg_str(&data, (const char *)argv[i]) < 0) {
                goto out;
            }

            if (i < MAX_TOTAL_ARGS - 1
                && __bpf_read_arg(&data, (const char *)spaces, 1) < 0) {
                goto out;
            }
        }

        if (data.args_size < MAX_ARGS_ARR - 4) {
            __bpf_read_arg(&data, (const char *)ellipsis, 3);
        }

    out:
        tasks.update(&pid, &data);
        return 0;
    }

    TRACEPOINT_PROBE(syscalls, sys_exit_execve)
    {

        u32 pid = bpf_get_current_pid_tgid();
        struct data_t *data = tasks.lookup(&pid);
        struct data_t data_tmp = {};
        bpf_get_current_comm(&data_tmp.comm, sizeof(data_tmp.comm));

        if (data != NULL) {

            PID_FILTER
            PpID_FILTER
            UID_FILTER
            COMM_FILTER

            tasks.delete(&pid);
        }

        return 0;
    }

"""

class CMDMonitor:
	def __init__(self, bpf_text):
		self.bpf_text = bpf_text
		self.b = BPF(text=self.bpf_text)
		self.b["events"].open_perf_buffer(self.print_event)

	def print_event(self, cpu, data, size):
		event = self.b["events"].event(data)
		printb(b"%-6d %-6d %-8s %-16s" % (event.pid, event.ppid, event.comm, event.argv))

	def run(self):
		while True:
			try:
				self.b.perf_buffer_poll()
			except KeyboardInterrupt:
				exit()


if __name__ == "__main__":

	examples = """examples:
	./cmddetect -p 181                 # Block the execve behavior of all processes whose pid is 181
	./cmddetect -P 180                 # Block the execve behavior of all processes whose ppid is 180
	./cmddetect -u 1000                # Block the execve behavior of all processes whose uid is 1000
	./cmddetect -n python              # Block the execve behavior of all processes whose comm is "python"
"""

	parser = argparse.ArgumentParser(description="Use Linux signal to block the execve behavior of a specific process")

	parser.add_argument("-p", "--pid", help="PID to filter (e.g., 123456)")
	parser.add_argument("-P", "--ppid", help="PPID to filter (e.g., 123455)")
	parser.add_argument("-u", "--uid", help="UID to filter (e.g., 1000)")
	parser.add_argument("-n", "--comm", help="COMM to filter (e.g., python)")
	args = parser.parse_args()

	if not any(vars(args).values()):
		parser.print_help()

	else:
		if args.pid:
			pid_text = """
				if(data->pid == %s ){
					data->retval = args->ret;
					events.perf_submit(args, data, sizeof(struct data_t));
					bpf_send_signal(9);
					return 0;
				}""" % args.pid
			bpf_text = bpf_text.replace('PID_FILTER', pid_text)
		else:
			bpf_text = bpf_text.replace('PID_FILTER', '')

		if args.ppid:
			ppid_text = """
				if(data->ppid == %s ){
					data->retval = args->ret;
					events.perf_submit(args, data, sizeof(struct data_t));
					bpf_send_signal(9);
					return 0;
				}""" % args.ppid
			bpf_text = bpf_text.replace('PpID_FILTER', ppid_text)
		else:
			bpf_text = bpf_text.replace('PpID_FILTER', '')

		if args.uid:
			uid_text = """
				if(data->uid == %s ){
					data->retval = args->ret;
					events.perf_submit(args, data, sizeof(struct data_t));
					bpf_send_signal(9);
					return 0;
				}""" % args.uid
			bpf_text = bpf_text.replace('UID_FILTER',uid_text)
		else:
			bpf_text = bpf_text.replace('UID_FILTER', '')

		if args.comm:
			comm_text = """

				char target_Comm[] = target_comm;
				int target_Len = target_len;
				int flag=1;

				int comm_len = 0;
				for(comm_len; comm_len < sizeof(data_tmp.comm); comm_len++){
					if (data_tmp.comm[comm_len] == '\\0') break;
				}

				if(comm_len == target_Len){
					int i=0;
					for(i;i<comm_len;i++){
						if(data_tmp.comm[i] != target_Comm[i]){

							flag = 0;
							break;
						}
					}
				}else{
					flag = 0;
				}

				if(flag){
					data->retval = args->ret;
					events.perf_submit(args, data, sizeof(struct data_t));
					bpf_send_signal(9);
					return 0;
				}

			"""
			comm_name = str(args.comm)
			comm_len = str(len(comm_name))
			comm_name = '"' + comm_name + '"'

			comm_text = comm_text.replace('target_comm',comm_name)
			comm_text = comm_text.replace('target_len',comm_len)

			bpf_text = bpf_text.replace('COMM_FILTER',comm_text)

		else:
			bpf_text = bpf_text.replace('COMM_FILTER', '')


		print("%-6s %-6s %-14s %-16s" % ("PID", "PPID", "COMM", "CMDLINE"))

		cmd_monitor = CMDMonitor(bpf_text)
		cmd_monitor.run()
