#include "recording.h"
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <time.h>
#include <pcap.h>
#include <curl/curl.h>
#include <inttypes.h>
#include "call.h"



static int pcap_create_spool_dir(const char *dirpath);
static int check_main_spool_dir(const char *spoolpath);

static void pcap_init(struct call *);

static ssize_t meta_write_sdp_pcap(struct recording *, struct iovec *sdp_iov, int iovcnt,
		       enum call_opmode opmode);

static void dump_packet_pcap(struct recording *recording, struct packet_stream *sink, str *s);

static int set_record_call(struct call *call, str recordcall);



static const struct recording_method methods[] = {
	{
		.name = "pcap",
		.create_spool_dir = pcap_create_spool_dir,
		.init_struct = pcap_init,
		.write_meta_sdp = meta_write_sdp_pcap,
		.dump_packet = dump_packet_pcap,
	},
	{
		.name = "proc",
		.create_spool_dir = check_main_spool_dir,
	},
};


// Global file reference to the spool directory.
static char *spooldir = NULL;
// Used for URL encoding functions
CURL *curl;

const struct recording_method *selected_recording_method;


/**
 * Initialize RTP Engine filesystem settings and structure.
 * Check for or create the RTP Engine spool directory.
 */
void recording_fs_init(const char *spoolpath, const char *method_str) {
	int i;

	curl = curl_easy_init();
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
		fprintf(stderr, "Error while setting up spool directory \"%s\".\n", spooldir);
		fprintf(stderr, "Please run `mkdir %s` and start rtpengine again.\n", spooldir);
		exit(-1);
	}
}

static int check_main_spool_dir(const char *spoolpath) {
	struct stat info;

	if (stat(spoolpath, &info) != 0) {
		fprintf(stderr, "Spool directory \"%s\" does not exist.\n", spoolpath);
		return FALSE;
	}
	if (!S_ISDIR(info.st_mode)) {
		fprintf(stderr, "Spool file exists, but \"%s\" is not a directory.\n", spoolpath);
		return FALSE;
	}
	return TRUE;
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
	struct stat info;
	int spool_good = TRUE;

	if (!check_main_spool_dir(spoolpath))
		return FALSE;

	// Spool directory exists. Make sure it has inner directories.
	int path_len = strlen(spoolpath);
	char meta_path[path_len + 10];
	char rec_path[path_len + 7];
	snprintf(meta_path, path_len + 10, "%s/metadata", spoolpath);
	snprintf(rec_path, path_len + 7, "%s/pcaps", spoolpath);

	if (stat(meta_path, &info) != 0) {
		fprintf(stdout, "Creating metadata directory \"%s\".\n", meta_path);
		mkdir(meta_path, 0777);
	} else if(!S_ISDIR(info.st_mode)) {
		fprintf(stderr, "metadata file exists, but \"%s\" is not a directory.\n", meta_path);
		spool_good = FALSE;
	}

	if (stat(rec_path, &info) != 0) {
		fprintf(stdout, "Creating pcaps directory \"%s\".\n", rec_path);
		mkdir(rec_path, 0777);
	} else if(!S_ISDIR(info.st_mode)) {
		fprintf(stderr, "pcaps file exists, but \"%s\" is not a directory.\n", rec_path);
		spool_good = FALSE;
	}

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
	int is_recording = set_record_call(call, recordcall);
	return is_recording;
}

static void pcap_init(struct call *call) {
	struct recording *recording = call->recording;

	//recording->recording_pd = NULL;
	//recording->recording_pdumper = NULL;
	// Wireshark starts at packet index 1, so we start there, too
	recording->pcap.packet_num = 1;
	mutex_init(&recording->pcap.recording_lock);
	meta_setup_file(recording, call->callid);

	// set up pcap file
	str *pcap_path = recording_setup_file(recording, call->callid);
	if (pcap_path != NULL && recording->pcap.recording_pdumper != NULL
	    && recording->pcap.meta_fp) {
		// Write the location of the PCAP file to the metadata file
		fprintf(recording->pcap.meta_fp, "%s\n\n", pcap_path->s);
	}
}

/**
 * Controls the setting of recording variables on a `struct call *`.
 * Sets the `record_call` value on the `struct call`, initializing the
 * recording struct if necessary.
 *
 * Returns a boolean for whether or not the call is being recorded.
 */
static int set_record_call(struct call *call, str recordcall) {
	if (!str_cmp(&recordcall, "yes")) {
		if (call->record_call == FALSE) {
			if (!spooldir) {
				ilog(LOG_ERR, "Call recording requested, but no spool directory configured");
				return FALSE;
			}
			ilog(LOG_NOTICE, "Turning on call recording.");
		}
		call->record_call = TRUE;
		if (call->recording == NULL) {
			call->recording = g_slice_alloc0(sizeof(struct recording));
			_rm(init_struct, call);
		}

		return TRUE;
	}

	if (!str_cmp(&recordcall, "no")) {
		if (call->record_call == TRUE) {
			ilog(LOG_NOTICE, "Turning off call recording.");
		}
		call->record_call = FALSE;
		// XXX close, free and terminate structures here?
	} else {
		ilog(LOG_INFO, "\"record-call\" flag %s is invalid flag.", recordcall.s);
	}
	return call->record_call;
}

/**
 * Create a call metadata file in a temporary location.
 * Attaches the filepath and the file pointer to the call struct.
 */
str *meta_setup_file(struct recording *recording, str callid) {
	if (spooldir == NULL) {
		// No spool directory was created, so we cannot have metadata files.
		return NULL;
	}

	int rand_bytes = 8;
	str *meta_filepath = malloc(sizeof(str));
	// We don't want weird characters like ":" or "@" showing up in filenames
	char *escaped_callid = curl_easy_escape(curl, callid.s, callid.len);
	int escaped_callid_len = strlen(escaped_callid);
	// Length for spool directory path + "/tmp/rtpengine-meta-${CALLID}-"
	int mid_len = 20 + escaped_callid_len + 1 + 1;
	char suffix_chars[mid_len];
	snprintf(suffix_chars, mid_len, "/tmp/rtpengine-meta-%s-", escaped_callid);
	curl_free(escaped_callid);
	// Initially file extension is ".tmp". When call is over, it changes to ".txt".
	char *path_chars = rand_affixed_str(suffix_chars, rand_bytes, ".tmp");
	meta_filepath = str_init(meta_filepath, path_chars);
	recording->pcap.meta_filepath = meta_filepath;
	FILE *mfp = fopen(meta_filepath->s, "w");
	chmod(meta_filepath->s, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if (mfp == NULL) {
		ilog(LOG_ERROR, "Could not open metadata file: %s", meta_filepath->s);
		free(recording->pcap.meta_filepath->s);
		free(recording->pcap.meta_filepath);
		recording->pcap.meta_filepath = NULL;
	}
	recording->pcap.meta_fp = mfp;
	ilog(LOG_DEBUG, "Wrote metadata file to temporary path: %s", meta_filepath->s);
	return meta_filepath;
}

/**
 * Write out a block of SDP to the metadata file.
 */
static ssize_t meta_write_sdp_pcap(struct recording *recording, struct iovec *sdp_iov, int iovcnt,
		       enum call_opmode opmode)
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
int meta_finish_file(struct call *call) {
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
			fprintf(recording->pcap.meta_fp, "\n\n%s\n", recording->metadata->s);
		free(recording->metadata);
		recording->metadata = NULL;
		fclose(recording->pcap.meta_fp);

		// Get the filename (in between its directory and the file extension)
		// and move it to the finished file location.
		// Rename extension to ".txt".
		int fn_len;
		char *meta_filename = strrchr(recording->pcap.meta_filepath->s, '/');
		char *meta_ext = NULL;
		if (meta_filename == NULL) {
			meta_filename = recording->pcap.meta_filepath->s;
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
		return_code = return_code || rename(recording->pcap.meta_filepath->s, new_metapath);
		if (return_code != 0) {
			ilog(LOG_ERROR, "Could not move metadata file \"%s\" to \"%s/metadata/\"",
					 recording->pcap.meta_filepath->s, spooldir);
		} else {
			ilog(LOG_INFO, "Moved metadata file \"%s\" to \"%s/metadata\"",
					 recording->pcap.meta_filepath->s, spooldir);
		}
	} else {
		ilog(LOG_INFO, "Trying to clean up recording meta file without a file pointer opened.");
	}
	if (recording != NULL && recording->pcap.meta_filepath != NULL) {
		free(recording->pcap.meta_filepath->s);
		free(recording->pcap.meta_filepath);
	}
	mutex_destroy(&recording->pcap.recording_lock);

	return return_code;
}

/**
 * Generate a random PCAP filepath to write recorded RTP stream.
 * Returns path to created file.
 */
str *recording_setup_file(struct recording *recording, str callid) {
	str *recording_path = NULL;
	if (spooldir != NULL
      && recording != NULL
	    && recording->pcap.recording_pd == NULL && recording->pcap.recording_pdumper == NULL) {
		int rand_bytes = 8;
		// We don't want weird characters like ":" or "@" showing up in filenames
		char *escaped_callid = curl_easy_escape(curl, callid.s, callid.len);
		int escaped_callid_len = strlen(escaped_callid);
		// Length for spool directory path + "/pcaps/${CALLID}-"
		int rec_path_len = strlen(spooldir) + 7 + escaped_callid_len + 1 + 1;
		char rec_path[rec_path_len];
		snprintf(rec_path, rec_path_len, "%s/pcaps/%s-", spooldir, escaped_callid);
		curl_free(escaped_callid);
		char *path_chars = rand_affixed_str(rec_path, rand_bytes, ".pcap");

		recording_path = malloc(sizeof(str));
		recording_path = str_init(recording_path, path_chars);
		recording->pcap.recording_path = recording_path;

		recording->pcap.recording_pd = pcap_open_dead(DLT_RAW, 65535);
		recording->pcap.recording_pdumper = pcap_dump_open(recording->pcap.recording_pd, path_chars);
		if (recording->pcap.recording_pdumper == NULL) {
			pcap_close(recording->pcap.recording_pd);
			recording->pcap.recording_pd = NULL;
			ilog(LOG_INFO, "Failed to write recording file: %s", recording_path->s);
		} else {
			ilog(LOG_INFO, "Writing recording file: %s", recording_path->s);
		}
	} else if (recording != NULL) {
		recording->pcap.recording_path = NULL;
		recording->pcap.recording_pd = NULL;
		recording->pcap.recording_pdumper = NULL;
	}

	return recording_path;
}

/**
 * Flushes PCAP file, closes the dumper and descriptors, and frees object memory.
 */
void recording_finish_file(struct recording *recording) {
	if (recording->pcap.recording_pdumper != NULL) {
		pcap_dump_flush(recording->pcap.recording_pdumper);
		pcap_dump_close(recording->pcap.recording_pdumper);
		free(recording->pcap.recording_path->s);
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
