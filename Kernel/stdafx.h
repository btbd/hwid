#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ata.h>
#include <scsi.h>
#include <ntddndis.h>
#include <mountmgr.h>
#include <mountdev.h>
#include <classpnp.h>
#include <ntimage.h>

#include "util.h"
#include "hook.h"

static DWORD SEED = 0;
static CHAR SERIAL[] = "---------";

typedef struct _NIC_DRIVER {
	PDRIVER_OBJECT DriverObject;
	PDRIVER_DISPATCH Original;
} NIC_DRIVER, *PNIC_DRIVER;