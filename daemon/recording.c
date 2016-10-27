#include "recording.h"
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <time.h>
#include <pcap.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>

#include "call.h"
#include "kernel.h"



static int check_main_spool_dir(const char *spoolpath);
static char *recording_setup_file(struct recording *recording);
static char *meta_setup_file(struct recording *recording);
static void dummy();

// pcap methods
static int pcap_create_spool_dir(const char *dirpath);
static void pcap_init(struct call *);
static ssize_t meta_write_sdp_pcap(struct recording *, struct iovec *sdp_iov, int iovcnt,
		       unsigned int str_len, enum call_opmode opmode);
static void dump_packet_pcap(struct recording *recording, struct packet_stream *sink, str *s);
static void finish_pcap(struct call *);

// proc methods
static void proc_init(struct call *);
static ssize_t meta_write_sdp_proc(struct recording *, struct iovec *sdp_iov, int iovcnt,
		       unsigned int str_len, enum call_opmode opmode);
static void finish_proc(struct call *);
static void dump_packet_proc(struct recording *recording, struct packet_stream *sink, str *s);
static void setup_stream_proc(struct packet_stream *);



static const struct recording_method methods[] = {
	{
		.name = "pcap",
		.kernel_support = 0,
		.create_spool_dir = pcap_create_spool_dir,
		.init_struct = pcap_init,
		.write_meta_sdp = meta_write_sdp_pcap,
		.dump_packet = dump_packet_pcap,
		.finish = finish_pcap,
		.setup_stream = dummy,
	},
	{
		.name = "proc",
		.kernel_support = 1,
		.create_spool_dir = check_main_spool_dir,
		.init_struct = proc_init,
		.write_meta_sdp = meta_write_sdp_proc,
		.dump_packet = dump_packet_proc,
		.finish = finish_proc,
		.setup_stream = setup_stream_proc,
	},
};


// Global file reference to the spool directory.
static char *spooldir = NULL;

const struct recording_method *selected_recording_method;




static void dummy() {
	;
}


/**
 * Initialize RTP Engine filesystem settings and structure.
 * Check for or create the RTP Engine spool directory.
 */
void recording_fs_init(const char *spoolpath, const char *method_str) {
	int i;

	// Whether or not to fail if the spool directory does not exist.
	if (spoolpath == NULL || spoolpath[0] == '\0')
		return;

	for (i = 0; i < G_N_ELEMENTS(methods); i++) {
		if (!strcmp(methods[i].name, method_str)) {
			selected_recording_method = &methods[i];
			goto found;
		}
	}

	ilog(LOG_ERROR, "Recording method '%s' not supported", method_str);
	return;

found:
	spooldir = strdup(spoolpath);

	int path_len = strlen(spooldir);
	// Get rid of trailing "/" if it exists. Other code adds that in when needed.
	if (spooldir[path_len-1] == '/') {
		spooldir[path_len-1] = '\0';
	}
	if (!_rm(create_spool_dir, spooldir)) {
		// XXX replace fprintf with ilog
		fprintf(stderr, "Error while setting up spool directory \"%s\".\n", spooldir);
		fprintf(stderr, "Please run `mkdir %s` and start rtpengine again.\n", spooldir);
		exit(-1);
	}
}

static int check_create_dir(const char *dir, const char *desc, int creat) {
	struct stat info;

	if (stat(dir, &info) != 0) {
		if (!creat) {
			fprintf(stderr, "%s directory \"%s\" does not exist.\n", desc, dir);
			return FALSE;
		}
		fprintf(stdout, "Creating %s directory \"%s\".\n", desc, dir);
		if (mkdir(dir, 0777) == 0)
			return TRUE;
		fprintf(stdout, "Failed to create %s directory \"%s\": %s\n", desc, dir, strerror(errno));
		return FALSE;
	}
	if(!S_ISDIR(info.st_mode)) {
		fprintf(stderr, "%s file exists, but \"%s\" is not a directory.\n", desc, dir);
		return FALSE;
	}
	return TRUE;
}

static int check_main_spool_dir(const char *spoolpath) {
	return check_create_dir(spoolpath, "spool", 0);
}

/**
 * Sets up the spool directory for RTP Engine.
 * If the directory does not exist, return FALSE.
 * If the directory exists, but "$spoolpath/metadata" or "$spoolpath/pcaps"
 * exist as non-directory files, return FALSE.
 * Otherwise, return TRUE.
 *
 * Create the "metadata" and "pcaps" directories if they are not there.
 */
static int pcap_create_spool_dir(const char *spoolpath) {
	int spool_good = TRUE;

	if (!check_main_spool_dir(spoolpath))
		return FALSE;

	// Spool directory exists. Make sure it has inner directories.
	int path_len = strlen(spoolpath);
	char meta_path[path_len + 10];
	char rec_path[path_len + 7];
	char tmp_path[path_len + 5];
	snprintf(meta_path, sizeof(meta_path), "%s/metadata", spoolpath);
	snprintf(rec_path, sizeof(rec_path), "%s/pcaps", spoolpath);
	snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", spoolpath);

	if (!check_create_dir(meta_path, "metadata", 1))
		spool_good = FALSE;
	if (!check_create_dir(rec_path, "pcaps", 1))
		spool_good = FALSE;
	if (!check_create_dir(tmp_path, "tmp", 1))
		spool_good = FALSE;

	return spool_good;
}

/**
 *
 * Controls the setting of recording variables on a `struct call *`.
 * Sets the `record_call` value on the `struct call`, initializing the
 * recording struct if necessary.
 * If we do not yet have a PCAP file associated with the call, create it
 * and write its file URL to the metadata file.
 *
 * Returns a boolean for whether or not the call is being recorded.
 */
int detect_setup_recording(struct call *call, str recordcall) {
	if (!str_cmp(&recordcall, "yes")) {
		if (call->recording) // already active
			return TRUE;

		if (!spooldir) {
			ilog(LOG_ERR, "Call recording requested, but no spool directory configured");
			return FALSE;
		}
		ilog(LOG_NOTICE, "Turning on call recording.");

		call->recording = g_slice_alloc0(sizeof(struct recording));
		struct recording *recording = call->recording;
		recording->escaped_callid = g_uri_escape_string(call->callid.s, NULL, 0);
		const int rand_bytes = 8;
		char rand_str[rand_bytes * 2 + 1];
		rand_hex_str(rand_str, rand_bytes);
		if (asprintf(&recording->meta_prefix, "%s-%s", recording->escaped_callid, rand_str) < 0)
			abort();
		_rm(init_struct, call);

		return TRUE;
	}

	if (!str_cmp(&recordcall, "no")) {
		if (!call->recording)
			return FALSE;

		ilog(LOG_NOTICE, "Turning off call recording.");
		recording_finish(call);
	} else {
		ilog(LOG_INFO, "\"record-call\" flag "STR_FORMAT" is invalid flag.", STR_FMT(&recordcall));
	}
	return call->recording ? TRUE : FALSE;
}

static void pcap_init(struct call *call) {
	struct recording *recording = call->recording;

	//recording->recording_pd = NULL;
	//recording->recording_pdumper = NULL;
	// Wireshark starts at packet index 1, so we start there, too
	recording->pcap.packet_num = 1;
	mutex_init(&recording->pcap.recording_lock);
	meta_setup_file(recording);

	// set up pcap file
	char *pcap_path = recording_setup_file(recording);
	if (pcap_path != NULL && recording->pcap.recording_pdumper != NULL
	    && recording->pcap.meta_fp) {
		// Write the location of the PCAP file to the metadata file
		fprintf(recording->pcap.meta_fp, "%s\n\n", pcap_path);
	}
}

static char *file_path_str(const char *id, const char *prefix, const char *suffix) {
	char *ret;
	if (asprintf(&ret, "%s%s%s%s", spooldir, prefix, id, suffix) < 0)
		abort();
	return ret;
}

/**
 * Create a call metadata file in a temporary location.
 * Attaches the filepath and the file pointer to the call struct.
 */
static char *meta_setup_file(struct recording *recording) {
	if (spooldir == NULL) {
		// No spool directory was created, so we cannot have metadata files.
		return NULL;
	}

	char *meta_filepath = file_path_str(recording->meta_prefix, "/tmp/rtpengine-meta-", ".tmp");
	recording->meta_filepath = meta_filepath;
	FILE *mfp = fopen(meta_filepath, "w");
	chmod(meta_filepath, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if (mfp == NULL) {
		ilog(LOG_ERROR, "Could not open metadata file: %s", meta_filepath);
		free(meta_filepath);
		recording->meta_filepath = NULL;
		return NULL;
	}
	recording->pcap.meta_fp = mfp;
	ilog(LOG_DEBUG, "Wrote metadata file to temporary path: %s", meta_filepath);
	return meta_filepath;
}

/**
 * Write out a block of SDP to the metadata file.
 */
static ssize_t meta_write_sdp_pcap(struct recording *recording, struct iovec *sdp_iov, int iovcnt,
		       unsigned int str_len, enum call_opmode opmode)
{
	FILE *meta_fp = recording->pcap.meta_fp;
	if (!meta_fp)
		return 0;

	int meta_fd = fileno(meta_fp);
	// File pointers buffer data, whereas direct writing using the file
	// descriptor does not. Make sure to flush any unwritten contents
	// so the file contents appear in order.
	fprintf(meta_fp, "\nSDP mode: ");
	if (opmode == OP_ANSWER) {
		fprintf(meta_fp, "answer");
	} else if (opmode == OP_OFFER) {
		fprintf(meta_fp, "offer");
	} else {
		fprintf(meta_fp, "other");
	}
	fprintf(meta_fp, "\nSDP before RTP packet: %" PRIu64 "\n\n", recording->pcap.packet_num);
	fflush(meta_fp);
	return writev(meta_fd, sdp_iov, iovcnt);
}

/**
 * Writes metadata to metafile, closes file, and renames it to finished location.
 * Returns non-zero for failure.
 */
static int pcap_meta_finish_file(struct call *call) {
	// This should usually be called from a place that has the call->master_lock
	struct recording *recording = call->recording;
	int return_code = 0;

	if (recording != NULL && recording->pcap.meta_fp != NULL) {
		// Print start timestamp and end timestamp
		// YYYY-MM-DDThh:mm:ss
		time_t start = call->created;
		time_t end = g_now.tv_sec;
		char timebuffer[20];
		struct tm *timeinfo;
		timeinfo = localtime(&start);
		strftime(timebuffer, 20, "%FT%T", timeinfo);
		fprintf(recording->pcap.meta_fp, "\n\ncall start time: %s\n", timebuffer);
		timeinfo = localtime(&end);
		strftime(timebuffer, 20, "%FT%T", timeinfo);
		fprintf(recording->pcap.meta_fp, "call end time: %s\n", timebuffer);

		// Print metadata
		if (recording->metadata)
			fprintf(recording->pcap.meta_fp, "\n\n"STR_FORMAT"\n", STR_FMT(recording->metadata));
		fclose(recording->pcap.meta_fp);

		// Get the filename (in between its directory and the file extension)
		// and move it to the finished file location.
		// Rename extension to ".txt".
		int fn_len;
		char *meta_filename = strrchr(recording->meta_filepath, '/');
		char *meta_ext = NULL;
		if (meta_filename == NULL) {
			meta_filename = recording->meta_filepath;
		}
		else {
			meta_filename = meta_filename + 1;
		}
		// We can always expect a file extension
		meta_ext = strrchr(meta_filename, '.');
		fn_len = meta_ext - meta_filename;
		int prefix_len = strlen(spooldir) + 10; // constant for "/metadata/" suffix
		int ext_len = 4;     // for ".txt"
		char new_metapath[prefix_len + fn_len + ext_len + 1];
		snprintf(new_metapath, prefix_len+fn_len+1, "%s/metadata/%s", spooldir, meta_filename);
		snprintf(new_metapath + prefix_len+fn_len, ext_len+1, ".txt");
		return_code = return_code || rename(recording->meta_filepath, new_metapath);
		if (return_code != 0) {
			ilog(LOG_ERROR, "Could not move metadata file \"%s\" to \"%s/metadata/\"",
					 recording->meta_filepath, spooldir);
		} else {
			ilog(LOG_INFO, "Moved metadata file \"%s\" to \"%s/metadata\"",
					 recording->meta_filepath, spooldir);
		}
	} else {
		ilog(LOG_INFO, "Trying to clean up recording meta file without a file pointer opened.");
	}
	mutex_destroy(&recording->pcap.recording_lock);

	return return_code;
}

/**
 * Generate a random PCAP filepath to write recorded RTP stream.
 * Returns path to created file.
 */
static char *recording_setup_file(struct recording *recording) {
	char *recording_path = NULL;

	if (!spooldir)
		return NULL;
	if (recording->pcap.recording_pd || recording->pcap.recording_pdumper)
		return NULL;

	recording_path = file_path_str(recording->meta_prefix, "/pcaps/", ".pcap");
	recording->pcap.recording_path = recording_path;

	recording->pcap.recording_pd = pcap_open_dead(DLT_RAW, 65535);
	recording->pcap.recording_pdumper = pcap_dump_open(recording->pcap.recording_pd, recording_path);
	if (recording->pcap.recording_pdumper == NULL) {
		pcap_close(recording->pcap.recording_pd);
		recording->pcap.recording_pd = NULL;
		ilog(LOG_INFO, "Failed to write recording file: %s", recording_path);
	} else {
		ilog(LOG_INFO, "Writing recording file: %s", recording_path);
	}

	return recording_path;
}

/**
 * Flushes PCAP file, closes the dumper and descriptors, and frees object memory.
 */
static void pcap_recording_finish_file(struct recording *recording) {
	if (recording->pcap.recording_pdumper != NULL) {
		pcap_dump_flush(recording->pcap.recording_pdumper);
		pcap_dump_close(recording->pcap.recording_pdumper);
		free(recording->pcap.recording_path);
	}
	if (recording->pcap.recording_pd != NULL) {
		pcap_close(recording->pcap.recording_pd);
	}
}

/**
 * Write out a PCAP packet with payload string.
 * A fair amount extraneous of packet data is spoofed.
 */
static void stream_pcap_dump(pcap_dumper_t *pdumper, struct packet_stream *stream, str *s) {
	if (!pdumper)
		return;

	endpoint_t src_endpoint = stream->advertised_endpoint;
	endpoint_t dst_endpoint = stream->selected_sfd->socket.local;

	// Wrap RTP in fake UDP packet header
	// Right now, we spoof it all
	u_int16_t udp_len = ((u_int16_t)s->len) + 8;
	u_int16_t udp_header[4];
	u_int16_t src_port = (u_int16_t) src_endpoint.port;
	u_int16_t dst_port = (u_int16_t) dst_endpoint.port;
	udp_header[0] = htons(src_port); // source port
	udp_header[1] = htons(dst_port); // destination port
	udp_header[2] = htons(udp_len); // packet length
	udp_header[3] = 0; // checksum

	// Wrap RTP in fake IP packet header
	u_int8_t ip_header[20];
	u_int16_t ip_total_length = udp_len + 20;
	u_int16_t *ip_total_length_ptr = (u_int16_t*)(ip_header + 2);
	u_int32_t *ip_src_addr = (u_int32_t*)(ip_header + 12);
	u_int32_t *ip_dst_addr = (u_int32_t*)(ip_header + 16);
	unsigned long src_ip = src_endpoint.address.u.ipv4.s_addr;
	unsigned long dst_ip = dst_endpoint.address.u.ipv4.s_addr;
	memset(ip_header, 0, 20);
	ip_header[0] = 4 << 4; // IP version - 4 bits
	ip_header[0] = ip_header[0] | 5; // Internet Header Length (IHL) - 4 bits
	ip_header[1] = 0; // DSCP - 6 bits
	ip_header[1] = 0; // ECN - 2 bits
	*ip_total_length_ptr = htons(ip_total_length);
	ip_header[4] = 0; ip_header[5] = 0 ; // Identification - 2 bytes
	ip_header[6] = 0; // Flags - 3 bits
	ip_header[7] = 0; // Fragment Offset - 13 bits
	ip_header[8] = 64; // TTL - 1 byte
	ip_header[9] = 17; // Protocol (defines protocol in data portion) - 1 byte
	ip_header[10] = 0; ip_header[11] = 0; // Header Checksum - 2 bytes
	*ip_src_addr = src_ip; // Source IP (set to localhost) - 4 bytes
	*ip_dst_addr = dst_ip; // Destination IP (set to localhost) - 4 bytes

	// Set up PCAP packet header
	struct pcap_pkthdr header;
	ZERO(header);
	header.ts = g_now;
	header.caplen = s->len + 28;
	// This must be the same value we use in `pcap_open_dead`
	header.len = s->len + 28;

	// Copy all the headers and payload into a new string
	unsigned char pkt_s[ip_total_length];
	memcpy(pkt_s, ip_header, 20);
	memcpy(pkt_s + 20, udp_header, 8);
	memcpy(pkt_s + 28, s->s, s->len);

	// Write the packet to the PCAP file
	// Casting quiets compiler warning.
	pcap_dump((unsigned char *)pdumper, &header, (unsigned char *)pkt_s);
}

static void dump_packet_pcap(struct recording *recording, struct packet_stream *stream, str *s) {
	mutex_lock(&recording->pcap.recording_lock);
	stream_pcap_dump(recording->pcap.recording_pdumper, stream, s);
	recording->pcap.packet_num++;
	mutex_unlock(&recording->pcap.recording_lock);
}

static void finish_pcap(struct call *call) {
	pcap_recording_finish_file(call->recording);
	pcap_meta_finish_file(call);
}

void recording_finish(struct call *call) {
	if (!call || !call->recording)
		return;

	struct recording *recording = call->recording;

	_rm(finish, call);

	free(recording->meta_prefix);
	free(recording->escaped_callid);
	free(recording->metadata);
	free(recording->meta_filepath);

	g_slice_free1(sizeof(*(recording)), recording);
	call->recording = NULL;
}








static int open_proc_meta_file(struct recording *recording) {
	int fd;
	fd = open(recording->meta_filepath, O_WRONLY | O_APPEND | O_CREAT, 0666);
	if (fd == -1) {
		ilog(LOG_ERR, "Failed to open recording metadata file '%s' for writing: %s",
				recording->meta_filepath, strerror(errno));
		return -1;
	}
	return fd;
}

static void proc_init(struct call *call) {
	struct recording *recording = call->recording;
	struct callmaster *cm = call->callmaster;

	recording->proc.call_idx = UNINIT_IDX;
	if (cm->conf.kernelid < 0 || cm->conf.kernelfd < 0) {
		ilog(LOG_WARN, "Call recording through /proc interface requested, but kernel table not open");
		return;
	}
	recording->proc.call_idx = kernel_add_call(cm->conf.kernelfd, recording->meta_prefix);
	if (recording->proc.call_idx == UNINIT_IDX) {
		ilog(LOG_ERR, "Failed to add call to kernel recording interface: %s", strerror(errno));
		return;
	}
	ilog(LOG_DEBUG, "kernel call idx is %u", recording->proc.call_idx);

	recording->meta_filepath = file_path_str(recording->meta_prefix, "/", ".meta");
	unlink(recording->meta_filepath); // start fresh XXX good idea?
}

static ssize_t meta_write_sdp_proc(struct recording *recording, struct iovec *sdp_iov, int iovcnt,
		       unsigned int str_len, enum call_opmode opmode)
{
	int fd = open_proc_meta_file(recording);
	if (fd == -1)
		return -1;

	char buf[128];
	int prlen = snprintf(buf, sizeof(buf), "SDP\n%u:\n", str_len); // XXX more details here

	// use writev for an atomic write
	struct iovec iov[iovcnt + 2];
	iov[0].iov_base = buf;
	iov[0].iov_len = prlen;
	memcpy(&iov[1], sdp_iov, iovcnt * sizeof(*iov));
	iov[iovcnt + 1].iov_base = "\n\n";
	iov[iovcnt + 1].iov_len = 2;

	if (writev(fd, iov, iovcnt + 2) != (str_len + prlen + 2))
		ilog(LOG_WARN, "writev return value incorrect");

	close(fd); // this triggers the inotify

	return 0;
}

static void finish_proc(struct call *call) {
	struct callmaster *cm = call->callmaster;
	struct recording *recording = call->recording;
	// XXX these checks are redundant. globalize into a struct
	if (cm->conf.kernelid < 0 || cm->conf.kernelfd < 0)
		return;
	if (recording->proc.call_idx != UNINIT_IDX)
		kernel_del_call(cm->conf.kernelfd, recording->proc.call_idx);
	// XXX unlink meta file??
}

static void setup_stream_proc(struct packet_stream *stream) {
	struct call *call = stream->call;
	struct callmaster *cm = call->callmaster;

	stream->recording.proc.stream_idx = UNINIT_IDX;

	if (!call->recording)
		return;
	if (cm->conf.kernelfd < 0 || cm->conf.kernelid < 0)
		return;

	char stream_id[128];
	// XXX include tag from/to
	snprintf(stream_id, sizeof(stream_id), "media-%u-component-%u-%s-id-%u",
			stream->media->index,
			stream->component,
			(PS_ISSET(stream, RTCP) && !PS_ISSET(stream, RTP)) ? "RTCP" : "RTP",
			stream->unique_id);
	stream->recording.proc.stream_idx = kernel_add_intercept_stream(cm->conf.kernelfd,
			call->recording->proc.call_idx, stream_id);
	if (stream->recording.proc.stream_idx == UNINIT_IDX) {
		ilog(LOG_ERR, "Failed to add stream to kernel recording interface: %s", strerror(errno));
		return;
	}
	ilog(LOG_DEBUG, "kernel stream idx is %u", stream->recording.proc.stream_idx);
}

static void dump_packet_proc(struct recording *recording, struct packet_stream *stream, str *s) {
}
