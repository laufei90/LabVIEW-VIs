#include "extcode.h"
#include "pcap.h"

#define EXPORT __declspec(dllexport)

pcap_if_t *gDevices = NULL;

static MgErr SetString(const char *src, LStrHandle *dest)
{
	int32 len = 0;
	if (src) {
		len = (int32)strlen(src);
	}
	MgErr err = mgNoErr;
	if (dest) {
		if (*dest) {
			err = DSSetHandleSize(*dest, sizeof(int32) + len);
		}
		else {
			*dest = (LStrHandle)DSNewHandle(sizeof(int32) + len);
		}
		if (*dest) {
			if (!err) {
				LStrLen(**dest) = len;
				if (src) {
					memcpy(LStrBuf(**dest), src, len);
				}
			}
		}
		else {
			err = mFullErr;
		}
	}
	else {
		err = mgArgErr;
	}
	return err;
}



EXTERNC EXPORT int32 lvwpcap_init(LStrHandle *error_string)
{
	char tempbuf[PCAP_ERRBUF_SIZE];
	int32 err = pcap_findalldevs(&gDevices, tempbuf);
	if (err == -1) {
		// error case. copy over the error string.
		SetString(tempbuf, error_string);
	}
	else {
		SetString(NULL, error_string);
	}
	return err;
}

EXTERNC EXPORT int32 lvwpcap_uninit(LStrHandle *error_string)
{
	if (gDevices) {
		pcap_freealldevs(gDevices);
	}
	SetString(NULL, error_string);
	return 0;
}

EXTERNC EXPORT int32 lvwpcap_get_interface_count()
{
	int32 n = 0;
	pcap_if_t *d = gDevices;
	while (d) {
		d = d->next;
		++n;
	}
	return n;
}

EXTERNC EXPORT int32 lvwpcap_get_interface(int32 index, LStrHandle *name, LStrHandle *description, LStrHandle *error_string)
{
	int32 retval = 0;
	int32 i;
	pcap_if_t *d = gDevices;
	for (i = 0; i < index; ++i) {
		if (d) {
			d = d->next;
		}
	}
	if (d) {
		SetString(d->name, name);
		SetString(d->description, description);
	}
	else {
		retval = -1;
		SetString("lvwpcap_get_interface: invalid interface index", error_string);
	}
	return retval;
}

EXTERNC EXPORT int32 lvwpcap_open_interface(int32 index,
											int32 capture_size,
											int32 promiscuous_mode,
											int32 read_timeout,
											uInt32 *pcap,
											LStrHandle *error_string)
{
	int32 retval = 0;
	int32 i;
	pcap_if_t *d = gDevices;
	for (i = 0; i < index; ++i) {
		if (d) {
            d = d->next;
		}
	}
	if (d) {
		if (capture_size > 65536) {
			capture_size = 65536;
		}
		if (capture_size < 0) {
			capture_size = 256;
		}
		char tempbuf[PCAP_ERRBUF_SIZE];
		pcap_t *p = pcap_open_live(d->name, capture_size, promiscuous_mode, read_timeout, tempbuf);
		if (p) {
			*pcap = (uInt32)p;  // give to LV as a "refnum" of sorts.
		}
		else {
			retval = -1;
			SetString(tempbuf, error_string);
		}
	}
	else {
		retval = -1;
		SetString("lvwpcap_open_interface: invalid interface index", error_string);
	}
	return retval;
}

EXTERNC EXPORT int32 lvwpcap_close_interface(uInt32 pcap, LStrHandle *error_string)
{
	pcap_t *p = (pcap_t *)pcap;
	if (p) {
		pcap_close(p);
	}
	return 0;
}

EXTERNC EXPORT int32 lvwpcap_read_packet(uInt32 pcap,
										 uInt32 *tv_sec,
										 uInt32 *tv_usec,
										 uInt32 *capture_len,
										 LStrHandle capture_data)
{
	struct pcap_pkthdr *header;
	const u_char *data;

	int32 retval = pcap_next_ex((pcap_t *)pcap, &header, &data);
	if (retval > 0) {
		*tv_sec = header->ts.tv_sec;
		*tv_usec = header->ts.tv_usec;
		*capture_len = header->caplen;

		// avoid costly memory allocation.  assume string is at least 64K
		// (or whatever we set the max size to with our init call.
		memcpy(LStrBuf(*capture_data), data, header->caplen);
	}

	return retval;
}
