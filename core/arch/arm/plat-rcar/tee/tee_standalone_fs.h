/*
 * Copyright (c) 2016-2017, Renesas Electronics Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TEE_STANDALONE_FS_H
#define TEE_STANDALONE_FS_H

#include <drivers/qspi_hyper_flash.h>
#include "tee_standalone_fs_key_manager.h"

#if ((STANDALONE_FS_SECTOR_ADDR % SECTOR_SIZE) != 0)
#error STANDALONE_FS_SECTOR_ADDR is not a multiple of SECTOR_SIZE.
#endif
#if ((STANDALONE_FS_SECTOR_NUM % 2) != 0)
#error STANDALONE_FS_SECTOR_NUM is not a multiple of 2.
#endif

#define SAVE_SECTOR_NUM			(STANDALONE_FS_SECTOR_NUM / 2)
#define SURFACE_NUM			(2)

#define PATH_MAX_LEN			(256)
#define PATH_MAX_SIZE			(PATH_MAX_LEN + 1)

#define RECORD_HEAD_SIZE		(64U)
#define RECORD_HEAD_ENC_OFFSET		(SAFS_IV_LEN + SAFS_TAG_LEN)
#define RECORD_HEAD_ENC_SIZE		(32U)
#define RECORD_META_MIN_SIZE		(48U)
#define RECORD_META_MAX_SIZE		(288U)
#define RECORD_META_ENC_OFFSET		(SAFS_TAG_LEN)
#define RECORD_META_FIXED_SIZE		(SAFS_TAG_LEN + SAFS_EK_SIZE)
#define RECORD_DATA_ENC_OFFSET		(SAFS_TAG_LEN)
#define RECORD_DATA_FIXED_SIZE		(SAFS_TAG_LEN)
#define TERM_INFO_SIZE			(48U)
#define TERM_INFO_ENC_OFFSET		(SAFS_IV_LEN + SAFS_TAG_LEN)
#define TERM_INFO_ENC_SIZE		(16U)
#define TERM_INFO_OFFSET		(SECTOR_SIZE - TERM_INFO_SIZE)

#define RECORD_DATA_BUF_SIZE		(SECTOR_SIZE - TERM_INFO_SIZE - \
					RECORD_HEAD_SIZE - RECORD_META_MIN_SIZE)

#define WRITE_CNT_DEFAULT		(255U)
#define WRITE_CNT_MIN			(1U)
#define WRITE_CNT_MAX			(254U)

#define SAFS_ATTR_MASK_FTYPE		(0x0001U)
#define SAFS_ATTR_MASK_IWUSR		(0x0002U)
#define SAFS_ATTR_MASK_IRUSR		(0x0004U)

#define SAFS_ATTR_DATA_FILE		(0x0000U)
#define SAFS_ATTR_DATA_DIR		(0x0001U)
#define SAFS_ATTR_DATA_IWUSR		(0x0002U)
#define SAFS_ATTR_DATA_IRUSR		(0x0004U)

#define PERFECT_MATCHING		(0U)
#define FORWARD_MATCHING		(1U)

#define RDESC_SECTOR_IDX_UNASSIGNED	(-1)

#define RDESC_CTRL_UNLINK		(0x00000001U)
#define RDESC_CTRL_DIRSTREAM		(0x00000002U)
#define RDESC_CTRL_DELETE		(0x00000004U)

/**
 * Non-volatile information. 'Record Head'
 */
struct spif_record_head {
	uint8_t iv[SAFS_IV_LEN];		/* Initial Vector */
	uint8_t tag[SAFS_TAG_LEN];		/* MAC */
	uint8_t mek[SAFS_EK_SIZE];		/* Meta Encryption Key */
	uint16_t attr;				/* Attribute */
	uint16_t path_len;			/* Path Length */
	uint32_t data_len;			/* Data Length */
	uint32_t hod;				/* Hash of Directory */
	uint32_t reserved;			/* Reserved */
};

/**
 * Non-volatile information. 'Record Meta'
 */
struct spif_record_meta {
	uint8_t tag[SAFS_TAG_LEN];		/* MAC */
	uint8_t dek[SAFS_EK_SIZE];		/* Data Encryption Key */
	char path[PATH_MAX_SIZE];		/* Path String */
};

/**
 * Non-volatile information. 'Record Data'
 */
struct spif_record_data {
	uint8_t tag[SAFS_TAG_LEN];		/* MAC */
	uint8_t data[];				/* Data Area */
};

/**
 * Non-volatile information. 'Record Information'
 */
struct spif_record_info {
	struct spif_record_head record_head;	/* Record Head */
	struct spif_record_meta record_meta;	/* Record Meta */
	struct spif_record_data *record_data;	/* Record Data */
};

/**
 * Non-volatile information. 'Termination Information'
 */
struct spif_term_info {
	uint8_t iv[SAFS_IV_LEN];		/* Initial Vector */
	uint8_t tag[SAFS_TAG_LEN];		/* MAC */
	uint32_t record_num;			/* Record Number */
	uint32_t empty_offset;			/* Empty Offset */
	uint8_t write_count;			/* Write Count */
	uint8_t reserved1[3];			/* Reserved 1 */
	uint32_t reserved2;			/* Reserved 2 */
};

/**
 * Other information. 'Find Information'
 */
struct spio_find_info {
	const char *path;
	size_t path_len;
	uint16_t attr_mask;
	uint16_t attr;
	uint32_t hod;
	uint32_t match_flag;
};

/**
 * Other information. 'Write data Information'
 */
struct spio_write_data {
	const void *data;
	size_t size;
};

/**
 * Volatile information. 'Sector Information'
 */
struct spim_sector_info {
	uint32_t sector_addr;
	struct spif_term_info term_info;
};

/**
 * Volatile information. 'Record Descriptor Information'
 */
struct spim_record_descriptor {
	struct spif_record_info record_info;
	int32_t sector_idx;
	uint32_t record_offset;
	uint32_t ref_count;
	uint32_t ctrl_flag;
	int32_t rd;
};

/**
 * Volatile information. 'File Descriptor Information'
 */
struct spim_file_descriptor {
	struct spim_record_descriptor *ag_rdesc; 	/* aggregation */
	int32_t fd;
};

/**
 * Volatile information. 'Directory Stream Information'
 */
struct tee_fs_dir {
	char dir[PATH_MAX_SIZE];
	struct spio_find_info finfo;
	struct spim_record_descriptor *search_rdesc;	/* composition */
	struct tee_fs_dirent dirent;
};

#endif /* TEE_STANDALONE_FS_H */
