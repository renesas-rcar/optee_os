// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2018, Renesas Electronics Corporation
 */

#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <assert.h>
#include <tee/tee_fs.h>
#include <tee/tee_pobj.h>
#include <kernel/handle.h>
#include <kernel/mutex.h>
#include <kernel/tee_misc.h>
#include <trace.h>
#include <initcall.h>

#include "tee_standalone_fs.h"
#include "platform_config.h"

static struct spim_sector_info g_sector[SURFACE_NUM][SAVE_SECTOR_NUM];
static int32_t g_current_surface[SAVE_SECTOR_NUM];
static struct handle_db g_fd_handle_db = HANDLE_DB_INITIALIZER;
static struct handle_db g_rd_handle_db = HANDLE_DB_INITIALIZER;
static struct mutex g_standalone_fs_mutex = MUTEX_INITIALIZER;
static TEE_Result g_standalone_fs_status = TEE_ERROR_STORAGE_NOT_AVAILABLE;
static uint8_t *g_work_buf;
static uint8_t *g_record_data_buf;
static struct spim_record_descriptor *g_record_data_rdesc;

static TEE_Result tee_standalone_fs_init(void);
static TEE_Result spi_init_sector_info(void);
static TEE_Result spi_get_status(void);
static TEE_Result spi_get_status_and_alloc_file(struct tee_pobj *po,
			char **pfile, size_t *len_out);
static TEE_Result spi_get_status_and_alloc_dir(const TEE_UUID *uuid,
			char **pdir, size_t *len_out);
static TEE_Result spi_alloc_file(struct tee_pobj *po, char **pfile,
			size_t *len_out);
static TEE_Result spi_alloc_path(struct tee_pobj *po, char **ppath,
			size_t *len_out);
static void spi_free_file(char *path);
static void spi_lock(void);
static void spi_unlock(void);
static TEE_Result spi_encrypt_term_info(const struct spif_term_info *term_info,
			uint8_t *encrypt_buf);
static TEE_Result spi_read_term_info(uint32_t sector_addr,
			struct spif_term_info *term_info);
static void spi_update_write_count(uint8_t *write_count);
static uint32_t spi_ceil_ek_size(uint32_t not_align_size);
static TEE_Result spi_check_sector_range(
			const struct spim_record_descriptor *rdesc,
			uint32_t inc_path_len, uint32_t inc_data_len);
static uint32_t spi_get_record_info_size(
			const struct spim_record_descriptor *rdesc);
static TEE_Result spi_assign_record_info(uint32_t assign_size,
			int32_t *sector_idx_out,
			uint32_t *record_offset_out);
static TEE_Result spi_write_record_info(struct spim_record_descriptor *rdesc,
			uint32_t new_size, uint32_t old_size);
static struct spim_record_descriptor *spi_create_record_info(
			const char *path, size_t path_len,
			uint16_t attr, const struct spio_write_data *wd,
			size_t wd_num, TEE_Result *res_out);
static TEE_Result spi_update_record_info(struct spim_record_descriptor *rdesc,
			uint32_t old_size);
static TEE_Result spi_delete_record_info(struct spim_record_descriptor *rdesc);
static TEE_Result spi_encrypt_record_info(
			const struct spif_record_info *record_info,
			uint8_t *encrypt_buf);
static TEE_Result spi_read_record_head(uint32_t flash_addr,
			struct spif_record_head *record_head);
static TEE_Result spi_read_record_meta(uint32_t flash_addr,
			const struct spif_record_head *record_head,
			struct spif_record_meta *record_meta);
static TEE_Result spi_read_record_data(struct spim_record_descriptor *rdesc);
static void spi_write_record_data(struct spif_record_info *record_info,
			const struct spio_write_data *wd, size_t wd_num);
static void spi_get_parent_dir(const char *path, size_t path_len,
			const char **parent_dir, size_t *parent_dir_len);
static void spi_get_filename(const char *path, size_t path_len,
			const char **filename);
static TEE_Result spi_get_hod_from_path(const char *path, size_t path_len,
			uint32_t *hod);
static TEE_Result spi_get_hod(const char *dir, size_t dir_len, uint32_t *hod);
static TEE_Result spi_find_file(const char *file, size_t file_len);
static TEE_Result spi_find_file_under_dir(const char *dir, size_t dir_len);
static TEE_Result spi_find_file_and_generate_rdesc(
			const char *file, size_t file_len,
			struct spim_record_descriptor **rdesc_out);
static TEE_Result spi_find_path_and_generate_rdesc(
			const struct spio_find_info *f,
			struct spim_record_descriptor **rdesc_out);
static TEE_Result spi_find_path(const struct spio_find_info *f);
static TEE_Result spi_search_flash_for_record_info(
			const struct spio_find_info *f,
			int32_t *search_sector_idx,
			uint32_t *search_record_offset,
			struct spif_record_info *record_info);
static TEE_Result spi_match_record_info(const struct spio_find_info *f,
			uint32_t flash_addr,
			struct spif_record_info *record_info,
			uint32_t *next_addr);
static struct spim_sector_info *spi_get_current_sector(int32_t sector_idx);
static struct spim_sector_info *spi_get_next_sector(int32_t sector_idx);
static void spi_commit_sector(int32_t sector_idx,
			const struct spif_term_info *new_term_info);
static struct spim_file_descriptor *spi_alloc_fdp(
			struct spim_record_descriptor *rdesc);
static void spi_free_fdp(struct spim_file_descriptor *fdp);
static struct spim_file_descriptor *spi_get_fdp(struct tee_file_handle *fh);
static struct spim_record_descriptor *spi_alloc_rdesc(
			const struct spif_record_head *record_head,
			const struct spif_record_meta *record_meta);
static void spi_free_rdesc(struct spim_record_descriptor *rdesc);
static struct spim_record_descriptor *spi_get_rdesc(int32_t rd);
static TEE_Result spi_find_rdesc(const struct spio_find_info *f,
			struct spim_record_descriptor **rdesc_out);
static void spi_update_rdesc(const struct spim_record_descriptor *update_rdesc,
			int32_t difference, uint32_t update_size);
static struct tee_fs_dir *spi_alloc_dirst(const char *dir, size_t dir_len);
static void spi_free_dirst(struct tee_fs_dir *dirst);
static TEE_Result spi_read_flash(uint32_t flash_addr, uint8_t *buf,
			size_t rsize);
static TEE_Result spi_erase_and_write_sector(uint32_t sector_addr,
			const uint8_t *encrypted_record_buf,
			uint32_t record_buf_size,
			const uint8_t *encrypted_term_info);

static TEE_Result tee_standalone_open(const char *file, size_t file_len,
			size_t *file_size, struct tee_file_handle **fh_out);
static TEE_Result tee_standalone_create(const char *file, size_t file_len,
			const struct spio_write_data *wd, size_t wd_num,
			bool overwrite, struct tee_file_handle **fh_out);
static void tee_standalone_close(struct spim_file_descriptor *fdp);
static TEE_Result tee_standalone_read(struct spim_file_descriptor *fdp,
			void *buf, size_t *buf_len, size_t fpos);
static TEE_Result tee_standalone_write(struct spim_file_descriptor *fdp,
			const void *buf, size_t buf_len, size_t fpos);
static TEE_Result tee_standalone_rename(const char *old_file, size_t old_len,
			const char *new_file, size_t new_len, bool overwrite);
static TEE_Result tee_standalone_remove(const char *file, size_t file_len);
static TEE_Result tee_standalone_truncate(struct spim_file_descriptor *fdp,
			size_t length);
static TEE_Result tee_standalone_opendir(const char *name,
			size_t name_len, struct tee_fs_dir **dirst_out);
static TEE_Result tee_standalone_readdir(struct tee_fs_dir *dirst,
			struct tee_fs_dirent **dirent_out);
static void tee_standalone_closedir(struct tee_fs_dir *dirst);

static TEE_Result standalone_fs_open(struct tee_pobj *po, size_t *size,
			struct tee_file_handle **fh);
static TEE_Result standalone_fs_create(struct tee_pobj *po, bool overwrite,
			const void *head, size_t head_size,
			const void *attr, size_t attr_size,
			const void *data, size_t data_size,
			struct tee_file_handle **fh);
static void standalone_fs_close(struct tee_file_handle **fh);
static TEE_Result standalone_fs_read(struct tee_file_handle *fh, size_t pos,
			void *buf, size_t *len);
static TEE_Result standalone_fs_write(struct tee_file_handle *fh, size_t pos,
			const void *buf, size_t len);
static TEE_Result standalone_fs_rename(struct tee_pobj *old_po,
			struct tee_pobj *new_po, bool overwrite);
static TEE_Result standalone_fs_remove(struct tee_pobj *po);
static TEE_Result standalone_fs_truncate(struct tee_file_handle *fh,
			size_t size);
static TEE_Result standalone_fs_opendir(const TEE_UUID *uuid,
			struct tee_fs_dir **d);
static TEE_Result standalone_fs_readdir(struct tee_fs_dir *d,
			struct tee_fs_dirent **ent);
static void standalone_fs_closedir(struct tee_fs_dir *d);

static TEE_Result tee_standalone_fs_init(void)
{
	TEE_Result res;
	uint32_t ret;

	res = tee_sfkm_init_key_manager();

	if (res == TEE_SUCCESS) {
		ret = qspi_hyper_flash_init();
		if (ret != FL_DRV_OK) {
			res = TEE_ERROR_TARGET_DEAD;
		}
	}

	if (res == TEE_SUCCESS) {
		res = spi_init_sector_info();
	}

	if (res == TEE_SUCCESS) {
		g_standalone_fs_status = res;
	}

	return res;
}

driver_init(tee_standalone_fs_init);

static TEE_Result spi_init_sector_info(void)
{
	TEE_Result res;
	int32_t i;
	int32_t j;
	uint32_t lsector_addr;
	struct spim_sector_info *sector;
	struct spim_sector_info *sector_curr;
	struct spim_sector_info *sector_next;
	uint8_t wcnt1;
	uint8_t wcnt2;
	uint8_t wcnt_match;

	(void)memset(g_sector, 0, sizeof(g_sector));
	(void)memset(g_current_surface, 0, sizeof(g_current_surface));
	g_work_buf = (uint8_t *)OPTEE_LOG_BASE + 204800U;
	g_record_data_buf = g_work_buf + SECTOR_SIZE; /* RECORD_DATA_BUF_SIZE */
	g_record_data_rdesc = NULL;
	lsector_addr = STANDALONE_FS_SECTOR_ADDR;

	for (i = 0; i < SURFACE_NUM; i++) {
		for (j = 0; j < SAVE_SECTOR_NUM; j++) {
			sector = &g_sector[i][j];
			res = spi_read_term_info(lsector_addr,
					&sector->term_info);
			if (res != TEE_SUCCESS) {
				if (res != TEE_ERROR_MAC_INVALID) {
					EMSG("term info read error!");
				}
				(void)memset(&sector->term_info, 0,
					sizeof(struct spif_term_info));
				sector->term_info.write_count =
					WRITE_CNT_DEFAULT;
				res = TEE_SUCCESS;
			}
			sector->sector_addr = lsector_addr;
			lsector_addr += SECTOR_SIZE;
		}
	}

	for (i = 0; i < SAVE_SECTOR_NUM; i++) {
		wcnt1 = g_sector[0][i].term_info.write_count;
		wcnt2 = g_sector[1][i].term_info.write_count;
		if (wcnt1 == wcnt2) {
			g_current_surface[i] = 1;
		} else if (wcnt1 > wcnt2) {
			if ((wcnt1 == WRITE_CNT_MAX) &&
			    (wcnt2 == WRITE_CNT_MIN)) {
				g_current_surface[i] = 0;
			} else {
				g_current_surface[i] = 1;
			}
		} else {
			if ((wcnt2 == WRITE_CNT_MAX) &&
			    (wcnt1 == WRITE_CNT_MIN)) {
				g_current_surface[i] = 1;
			} else {
				g_current_surface[i] = 0;
			}
		}

		if ((wcnt1 != WRITE_CNT_DEFAULT) &&
		    (wcnt2 != WRITE_CNT_DEFAULT)) {
			sector_curr = spi_get_current_sector(i);
			sector_next = spi_get_next_sector(i);
			wcnt_match = sector_next->term_info.write_count;
			spi_update_write_count(&wcnt_match);
			if (wcnt_match != sector_curr->term_info.write_count) {
				/* Write Count does not match */
				(void)memset(&sector_curr->term_info, 0,
					sizeof(struct spif_term_info));
				sector_curr->term_info.write_count =
					WRITE_CNT_DEFAULT;
				(void)memcpy(&sector_next->term_info,
					&sector_curr->term_info,
					sizeof(struct spif_term_info));
				g_current_surface[i] = 1;
				EMSG("reinit sector info");
			}
		}
	}

	return res;
}

static TEE_Result spi_get_status(void)
{
	return g_standalone_fs_status;
}

static TEE_Result spi_get_status_and_alloc_file(struct tee_pobj *po,
			char **pfile, size_t *len_out)
{
	TEE_Result res;

	res = spi_get_status();
	if (res == TEE_SUCCESS) {
		res = spi_alloc_file(po, pfile, len_out);
	}

	return res;
}

static TEE_Result spi_get_status_and_alloc_dir(const TEE_UUID *uuid,
			char **pdir, size_t *len_out)
{
	TEE_Result res;
	struct tee_pobj epo;

	res = spi_get_status();
	if (res == TEE_SUCCESS) {
		(void)memset(&epo, 0, sizeof(epo));
		epo.uuid = *uuid;
		epo.obj_id = NULL;
		epo.obj_id_len = 0U;
		res = spi_alloc_path(&epo, pdir, len_out);
	}

	return res;
}

static TEE_Result spi_alloc_file(struct tee_pobj *po, char **pfile,
			size_t *len_out)
{
	TEE_Result res;

	if ((po->obj_id != NULL) && (po->obj_id_len > 0U) &&
	    (po->obj_id_len <= TEE_OBJECT_ID_MAX_LEN)) {
		res = spi_alloc_path(po, pfile, len_out);
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
	}

	return res;
}

static TEE_Result spi_alloc_path(struct tee_pobj *po, char **ppath,
			size_t *len_out)
{
	TEE_Result res;
	const size_t dir_len = (sizeof(TEE_UUID) * 2U) + 1U;
	size_t file_len;
	char *mpath;
	size_t pos;

	file_len = (po->obj_id_len * 2U) + 1U;

	mpath = malloc(dir_len + file_len);

	if (mpath != NULL) {
		(void)memset(mpath, 0, dir_len + file_len);
		pos = tee_b2hs((uint8_t *)&po->uuid, (uint8_t *)mpath,
				sizeof(TEE_UUID), dir_len);
		if (po->obj_id_len > 0U) {
			mpath[pos] = '/';
			pos++;
			pos += tee_b2hs((uint8_t *)po->obj_id,
					(uint8_t *)mpath + pos,
					po->obj_id_len, file_len);
		}
		mpath[pos] = '\0';

		*ppath = (char *)mpath;
		*len_out = pos;
		DMSG("path=%s, len=%zu", mpath, pos);
		res = TEE_SUCCESS;
	} else {
		res = TEE_ERROR_OUT_OF_MEMORY;
	}

	return res;
}

static void spi_free_file(char *path)
{
	free(path);
}

static void spi_lock(void)
{
	mutex_lock(&g_standalone_fs_mutex);
}

static void spi_unlock(void)
{
	mutex_unlock(&g_standalone_fs_mutex);
}

static TEE_Result spi_encrypt_term_info(const struct spif_term_info *term_info,
			uint8_t *encrypt_buf)
{
	TEE_Result res;
	struct tee_sfkm_crypt_info c;

	c.data_in	= (const uint8_t *)&term_info->record_num;
	c.data_size	= TERM_INFO_ENC_SIZE;
	c.iv		= term_info->iv;
	c.iv_size	= SAFS_IV_LEN;

	res = tee_sfkm_encrypt_suk(&c,
			encrypt_buf + TERM_INFO_ENC_OFFSET,
			encrypt_buf + SAFS_IV_LEN,	/* Tag */
			encrypt_buf);			/* Encrypted IV */

	return res;
}

static TEE_Result spi_read_term_info(uint32_t sector_addr,
			struct spif_term_info *term_info)
{
	TEE_Result res;
	uint8_t encrypted_data[TERM_INFO_SIZE];
	struct tee_sfkm_crypt_info c;

	res = spi_read_flash(sector_addr + TERM_INFO_OFFSET,
			encrypted_data, sizeof(encrypted_data));

	if (res == TEE_SUCCESS) {
		c.data_in	= encrypted_data + TERM_INFO_ENC_OFFSET;
		c.data_size	= TERM_INFO_ENC_SIZE;
		c.iv		= encrypted_data;	/* Encrypted IV */
		c.iv_size	= SAFS_IV_LEN;

		res = tee_sfkm_decrypt_suk(&c,
				encrypted_data + SAFS_IV_LEN,	/* Tag */
				(uint8_t *)&term_info->record_num,
				term_info->iv);

		if (res == TEE_SUCCESS) {
			(void)memcpy(term_info->tag,
				encrypted_data + SAFS_IV_LEN,
				SAFS_TAG_LEN);
		}
	}

	return res;
}

static void spi_update_write_count(uint8_t *write_count)
{
	uint8_t new_count;

	new_count = *write_count;

	new_count--;
	if (new_count < WRITE_CNT_MIN) {
		new_count = WRITE_CNT_MAX;
	}

	*write_count = new_count;
}

static uint32_t spi_ceil_ek_size(uint32_t not_align_size)
{
	uint32_t ceil_size; /* ceil encryption key size */
	uint32_t mod_size;

	mod_size = not_align_size % SAFS_EK_SIZE;

	if (mod_size == 0U) {
		ceil_size = not_align_size;
	} else {
		ceil_size = not_align_size + (SAFS_EK_SIZE - mod_size);
	}

	return ceil_size;
}

static TEE_Result spi_check_sector_range(
			const struct spim_record_descriptor *rdesc,
			uint32_t inc_path_len, uint32_t inc_data_len)
{
	TEE_Result res;
	const struct spif_record_head *lrecord_head;
	struct spim_sector_info *sector;
	uint32_t empty_size;
	uint32_t old_size;
	uint32_t new_size;
	uint32_t increment_size;

	lrecord_head = &rdesc->record_info.record_head;
	sector = spi_get_current_sector(rdesc->sector_idx);

	empty_size = TERM_INFO_OFFSET - sector->term_info.empty_offset;
	old_size = spi_ceil_ek_size(lrecord_head->path_len) +
		spi_ceil_ek_size(lrecord_head->data_len);
	new_size = spi_ceil_ek_size(lrecord_head->path_len + inc_path_len) +
		spi_ceil_ek_size(lrecord_head->data_len + inc_data_len);
	if ((lrecord_head->data_len == 0U) && (inc_data_len > 0U)) {
		new_size += RECORD_DATA_FIXED_SIZE;
	}
	increment_size = new_size - old_size;

	if (increment_size <= empty_size) {
		res = TEE_SUCCESS;
	} else {
		res = TEE_ERROR_STORAGE_NO_SPACE;
		EMSG("Sector out of range");
	}

	return res;
}

static uint32_t spi_get_record_info_size(
			const struct spim_record_descriptor *rdesc)
{
	uint32_t rinfo_size;

	/* Record Head + Record Meta */
	rinfo_size = RECORD_HEAD_SIZE + RECORD_META_FIXED_SIZE +
		spi_ceil_ek_size(rdesc->record_info.record_head.path_len);

	if (rdesc->record_info.record_head.data_len > 0U) {
		/* Record Data */
		rinfo_size += RECORD_DATA_FIXED_SIZE + spi_ceil_ek_size(
			rdesc->record_info.record_head.data_len);
	}

	return rinfo_size;
}

static TEE_Result spi_assign_record_info(uint32_t assign_size,
			int32_t *sector_idx_out,
			uint32_t *record_offset_out)
{
	TEE_Result res;
	struct spim_sector_info *sector;
	int32_t lsector_idx;
	uint32_t empty_size;
	uint32_t max_empty_size = 0U;
	int32_t assign_sector_idx = 0;
	uint32_t assign_record_offset = 0U;

	for (lsector_idx = 0; lsector_idx < SAVE_SECTOR_NUM; lsector_idx++) {
		sector = spi_get_current_sector(lsector_idx);
		empty_size = TERM_INFO_OFFSET - sector->term_info.empty_offset;
		if ((assign_size <= empty_size) &&
		    (empty_size > max_empty_size)) {
			assign_sector_idx = lsector_idx;
			assign_record_offset = sector->term_info.empty_offset;
			max_empty_size = empty_size;
		}
	}

	if (max_empty_size > 0) {
		*sector_idx_out = assign_sector_idx;
		*record_offset_out = assign_record_offset;
		res = TEE_SUCCESS;
	} else {
		res = TEE_ERROR_STORAGE_NO_SPACE;
	}

	return res;
}

static TEE_Result spi_write_record_info(struct spim_record_descriptor *rdesc,
			uint32_t new_size, uint32_t old_size)
{
	TEE_Result res = TEE_SUCCESS;
	struct spim_sector_info *sector_current;
	struct spim_sector_info *sector_next;
	struct spif_term_info eterm_info; /* entity */
	uint32_t total_record_size;
	uint32_t upper_half_size;
	uint32_t bottom_half_size;
	uint32_t buf_offset = 0U;
	int32_t difference;
	uint8_t *enc_buf;
	uint8_t *enc_record_buf = NULL;
	const uint8_t uninit_iv[SAFS_IV_LEN] = {0};

	sector_current = spi_get_current_sector(rdesc->sector_idx);
	sector_next = spi_get_next_sector(rdesc->sector_idx);
	enc_buf = g_work_buf;

	difference = new_size - old_size;
	upper_half_size = rdesc->record_offset;
	bottom_half_size = sector_current->term_info.empty_offset -
			rdesc->record_offset - old_size;
	total_record_size = upper_half_size + new_size + bottom_half_size;

	if (total_record_size <= TERM_INFO_OFFSET) {
		if (upper_half_size > 0U) {
			res = spi_read_flash(
					sector_current->sector_addr,
					enc_buf,
					upper_half_size);
			if (res == TEE_SUCCESS) {
				buf_offset = upper_half_size;
			}
		}
		if ((res == TEE_SUCCESS) && (new_size > 0U)) {
			res = spi_encrypt_record_info(
					&rdesc->record_info,
					enc_buf + buf_offset);
			if (res == TEE_SUCCESS) {
				buf_offset += new_size;
			}
		}
		if ((res == TEE_SUCCESS) && (bottom_half_size > 0U)) {
			res = spi_read_flash(
					sector_current->sector_addr +
					upper_half_size + old_size,
					enc_buf + buf_offset,
					bottom_half_size);
			if (res == TEE_SUCCESS) {
				buf_offset += bottom_half_size;
			}
		}

		if (res == TEE_SUCCESS) {
			(void)memcpy(&eterm_info, &sector_current->term_info,
				sizeof(struct spif_term_info));
			if ((new_size > 0U) && (old_size == 0U)) {
				eterm_info.record_num++;
			} else if ((new_size == 0U) && (old_size > 0U)) {
				eterm_info.record_num--;
			} else {
				/* no operation */
			}
			eterm_info.empty_offset = buf_offset;
			spi_update_write_count(&eterm_info.write_count);
			if (memcmp(eterm_info.iv, uninit_iv, SAFS_IV_LEN)
			    == 0) {
				res = tee_sfkm_generate_random(eterm_info.iv,
						SAFS_IV_LEN);
			}
		}
		if (res == TEE_SUCCESS) {
			res = spi_encrypt_term_info(&eterm_info,
					&enc_buf[TERM_INFO_OFFSET]);
		}
		if (res == TEE_SUCCESS) {
			if (eterm_info.record_num > 0) {
				enc_record_buf = enc_buf;
			}
			res = spi_erase_and_write_sector(
					sector_next->sector_addr,
					enc_record_buf, buf_offset,
					&enc_buf[TERM_INFO_OFFSET]);
		}
		if (res == TEE_SUCCESS) {
			if ((bottom_half_size > 0U) && (difference != 0)) {
				spi_update_rdesc(rdesc, difference, new_size);
			}
			spi_commit_sector(rdesc->sector_idx, &eterm_info);
		}
	} else {
		res = TEE_ERROR_STORAGE_NO_SPACE;
	}

	return res;
}

static struct spim_record_descriptor *spi_create_record_info(
			const char *path, size_t path_len,
			uint16_t attr, const struct spio_write_data *wd,
			size_t wd_num, TEE_Result *res_out)
{
	struct spim_record_descriptor *rdesc;
	struct spif_record_info *lrecord_info;
	TEE_Result res;
	uint32_t assign_size;

	rdesc = spi_alloc_rdesc(NULL, NULL);
	if (rdesc != NULL) {
		lrecord_info = &rdesc->record_info;
		lrecord_info->record_head.attr = attr;
		lrecord_info->record_head.path_len = path_len;
		lrecord_info->record_head.data_len = 0U;
		(void)memcpy(lrecord_info->record_meta.path, path, path_len);

		spi_write_record_data(lrecord_info, wd, wd_num);

		assign_size = spi_get_record_info_size(rdesc);

		res = tee_sfkm_generate_random(
				lrecord_info->record_head.iv,
				SAFS_IV_LEN);
		if (res == TEE_SUCCESS) {
			res = tee_sfkm_generate_random(
					lrecord_info->record_head.mek,
					SAFS_EK_SIZE);
		}
		if (res == TEE_SUCCESS) {
			res = tee_sfkm_generate_random(
					lrecord_info->record_meta.dek,
					SAFS_EK_SIZE);
		}
		if (res == TEE_SUCCESS) {
			res = spi_get_hod_from_path(path, path_len,
					&lrecord_info->record_head.hod);
		}
		if (res == TEE_SUCCESS) {
			res = spi_assign_record_info(assign_size,
					&rdesc->sector_idx,
					&rdesc->record_offset);
		}
		if (res == TEE_SUCCESS) {
			res = spi_write_record_info(rdesc, assign_size, 0U);
		}
		if (res != TEE_SUCCESS) {
			spi_free_rdesc(rdesc);
			rdesc = NULL;
		}
	} else {
		res = TEE_ERROR_OUT_OF_MEMORY;
	}

	*res_out = res;

	return rdesc;
}

static TEE_Result spi_update_record_info(struct spim_record_descriptor *rdesc,
			uint32_t old_size)
{
	TEE_Result res;
	uint32_t new_size;
	struct spim_sector_info *sector;

	sector = spi_get_current_sector(rdesc->sector_idx);

	if (rdesc->record_offset < sector->term_info.empty_offset) {
		new_size = spi_get_record_info_size(rdesc);

		res = spi_write_record_info(rdesc, new_size, old_size);
	} else {
		res = TEE_ERROR_MAC_INVALID;
		EMSG("Sector destruction error!");
	}

	return res;
}

static TEE_Result spi_delete_record_info(struct spim_record_descriptor *rdesc)
{
	TEE_Result res;
	uint32_t old_size;

	old_size = spi_get_record_info_size(rdesc);

	res = spi_write_record_info(rdesc, 0U, old_size);
	if (res == TEE_SUCCESS) {
		rdesc->sector_idx = RDESC_SECTOR_IDX_UNASSIGNED;
		rdesc->record_offset = 0U;
	}

	return res;
}

static TEE_Result spi_encrypt_record_info(
			const struct spif_record_info *record_info,
			uint8_t *encrypt_buf)
{
	TEE_Result res;
	uint32_t meta_enc_size;
	uint32_t data_enc_size;
	struct tee_sfkm_crypt_info c;

	/* Record Head */
	c.data_in	= record_info->record_head.mek;
	c.data_size	= RECORD_HEAD_ENC_SIZE;
	c.iv		= record_info->record_head.iv;
	c.iv_size	= SAFS_IV_LEN;

	res = tee_sfkm_encrypt_suk(&c,
			encrypt_buf + RECORD_HEAD_ENC_OFFSET,
			encrypt_buf + SAFS_IV_LEN,	/* Tag */
			encrypt_buf);			/* Encrypted IV */

	/* Record Meta */
	if (res == TEE_SUCCESS) {
		encrypt_buf += RECORD_HEAD_SIZE;
		meta_enc_size = SAFS_EK_SIZE + spi_ceil_ek_size(
				record_info->record_head.path_len);

		c.data_in	= record_info->record_meta.dek;
		c.data_size	= meta_enc_size;
		c.iv		= record_info->record_head.iv;
		c.iv_size	= SAFS_IV_LEN;
		c.key		= record_info->record_head.mek;
		c.key_size	= SAFS_EK_SIZE;

		res = tee_sfkm_encrypt(&c,
				encrypt_buf + RECORD_META_ENC_OFFSET,
				encrypt_buf);		/* Tag */
	}

	/* Record Data */
	if ((res == TEE_SUCCESS) && (record_info->record_head.data_len > 0U)) {
		encrypt_buf += RECORD_META_ENC_OFFSET + meta_enc_size;
		data_enc_size = spi_ceil_ek_size(
				record_info->record_head.data_len);

		c.data_in	= &record_info->record_data->data[0];
		c.data_size	= data_enc_size;
		c.iv		= record_info->record_head.iv;
		c.iv_size	= SAFS_IV_LEN;
		c.key		= record_info->record_meta.dek;
		c.key_size	= SAFS_EK_SIZE;

		res = tee_sfkm_encrypt(&c,
				encrypt_buf + RECORD_DATA_ENC_OFFSET,
				encrypt_buf);		/* Tag */
	}

	return res;
}

static TEE_Result spi_read_record_head(uint32_t flash_addr,
			struct spif_record_head *record_head)
{
	TEE_Result res;
	uint8_t encrypted_data[RECORD_HEAD_SIZE];
	struct tee_sfkm_crypt_info c;

	res = spi_read_flash(flash_addr, encrypted_data,
			sizeof(encrypted_data));

	if (res == TEE_SUCCESS) {
		c.data_in	= encrypted_data + RECORD_HEAD_ENC_OFFSET;
		c.data_size	= RECORD_HEAD_ENC_SIZE;
		c.iv		= encrypted_data;	/* Encrypted IV */
		c.iv_size	= SAFS_IV_LEN;

		res = tee_sfkm_decrypt_suk(&c,
				encrypted_data + SAFS_IV_LEN,	/* Tag */
				record_head->mek,
				record_head->iv);

		if (res == TEE_SUCCESS) {
			(void)memcpy(record_head->tag,
				encrypted_data + SAFS_IV_LEN,
				SAFS_TAG_LEN);
		}
	}

	return res;
}

static TEE_Result spi_read_record_meta(uint32_t flash_addr,
			const struct spif_record_head *record_head,
			struct spif_record_meta *record_meta)
{
	TEE_Result res;
	uint32_t buf_size;
	uint8_t encrypted_data[RECORD_META_MAX_SIZE];
	struct tee_sfkm_crypt_info c;

	buf_size = RECORD_META_FIXED_SIZE + spi_ceil_ek_size(
			record_head->path_len);

	res = spi_read_flash(flash_addr, encrypted_data, buf_size);

	if (res == TEE_SUCCESS) {
		(void)memset(record_meta->path, 0, sizeof(record_meta->path));

		c.data_in	= encrypted_data + RECORD_META_ENC_OFFSET;
		c.data_size	= buf_size - RECORD_META_ENC_OFFSET;
		c.iv		= record_head->iv;
		c.iv_size	= SAFS_IV_LEN;
		c.key		= record_head->mek;
		c.key_size	= SAFS_EK_SIZE;

		res = tee_sfkm_decrypt(&c,
				encrypted_data,		/* Tag */
				record_meta->dek);

		if (res == TEE_SUCCESS) {
			(void)memcpy(record_meta->tag, encrypted_data,
				SAFS_TAG_LEN);
		}
	}

	return res;
}

static TEE_Result spi_read_record_data(struct spim_record_descriptor *rdesc)
{
	TEE_Result res;
	struct spif_record_info *lrecord_info;
	struct spim_sector_info *sector;
	struct tee_sfkm_crypt_info c;
	uint32_t flash_addr;
	uint32_t buf_size;
	uint8_t *encrypted_data;
	const uint32_t enc_offset = RECORD_DATA_ENC_OFFSET;

	if (rdesc->record_info.record_head.data_len == 0U) {
		res = TEE_ERROR_NO_DATA;
	} else if (rdesc == g_record_data_rdesc) {
		res = TEE_SUCCESS;
	} else {
		lrecord_info = &rdesc->record_info;
		sector = spi_get_current_sector(rdesc->sector_idx);
		flash_addr = sector->sector_addr + rdesc->record_offset +
			RECORD_HEAD_SIZE + RECORD_META_FIXED_SIZE +
			spi_ceil_ek_size(lrecord_info->record_head.path_len);
		encrypted_data = g_work_buf;
		buf_size = enc_offset +
			spi_ceil_ek_size(lrecord_info->record_head.data_len);

		res = spi_read_flash(flash_addr, encrypted_data, buf_size);

		if (res == TEE_SUCCESS) {
			c.data_in	= encrypted_data + enc_offset;
			c.data_size	= buf_size - enc_offset;
			c.iv		= lrecord_info->record_head.iv;
			c.iv_size	= SAFS_IV_LEN;
			c.key		= lrecord_info->record_meta.dek;
			c.key_size	= SAFS_EK_SIZE;

			res = tee_sfkm_decrypt(&c,
					encrypted_data,	/* Tag */
					&lrecord_info->record_data->data[0]);

			if (res == TEE_SUCCESS) {
				(void)memcpy(lrecord_info->record_data->tag,
					encrypted_data,
					SAFS_TAG_LEN);
				g_record_data_rdesc = rdesc;
			}
		}
	}

	return res;
}

static void spi_write_record_data(struct spif_record_info *record_info,
			const struct spio_write_data *wd, size_t wd_num)
{
	size_t i;
	uint32_t dpos = 0;

	for (i = 0; i < wd_num; i++) {
		if ((wd[i].data != NULL) && (wd[i].size > 0U)) {
			(void)memcpy(&record_info->record_data->data[dpos],
				wd[i].data, wd[i].size);
			dpos += wd[i].size;
		}
	}

	record_info->record_head.data_len = dpos;
}

static void spi_get_parent_dir(const char *path, size_t path_len,
			const char **parent_dir, size_t *parent_dir_len)
{
	int32_t pos;

	*parent_dir = path;
	*parent_dir_len = path_len;

	for (pos = (int32_t)path_len - 1; pos >= 0; pos--) {
		if (path[pos] == '/') {
			/* e.g. path = "foo/bar" --> parent_dir = "foo"
			 */
			*parent_dir = path;
			*parent_dir_len = pos;
			break;
		}
	}
}

static void spi_get_filename(const char *path, size_t path_len,
			const char **filename)
{
	int32_t pos;

	*filename = path;

	for (pos = (int32_t)path_len - 1; pos >= 0; pos--) {
		if (path[pos] == '/') {
			/* e.g. path = "foo/bar" --> filename = "bar"
			 */
			*filename = path + pos + 1;
			break;
		}
	}
}

static TEE_Result spi_get_hod_from_path(const char *path, size_t path_len,
			uint32_t *hod)
{
	TEE_Result res;
	const char *dir_str;
	size_t dir_len;

	spi_get_parent_dir(path, path_len, &dir_str, &dir_len);

	res = spi_get_hod(dir_str, dir_len, hod);

	return res;
}

static TEE_Result spi_get_hod(const char *dir, size_t dir_len, uint32_t *hod)
{
	TEE_Result res;
	uint8_t hash_buf[TEE_SHA256_HASH_SIZE];
	uint8_t *byte_ptr;

	res = tee_sfkm_generate_sha256((const uint8_t *)dir, dir_len, hash_buf);
	if (res == TEE_SUCCESS) {
		byte_ptr = (uint8_t *)hod;
		(void)memcpy(byte_ptr, hash_buf, sizeof(uint32_t));
	}

	return res;
}

static TEE_Result spi_find_file(const char *file, size_t file_len)
{
	TEE_Result res;
	struct spio_find_info f;

	res = spi_get_hod_from_path(file, file_len, &f.hod);
	if (res == TEE_SUCCESS) {
		f.path		= file;
		f.path_len	= file_len;
		f.attr_mask	= SAFS_ATTR_MASK_FTYPE;
		f.attr		= SAFS_ATTR_DATA_FILE;
		f.match_flag	= PERFECT_MATCHING;

		res = spi_find_path(&f);
	}

	return res;
}

static TEE_Result spi_find_file_under_dir(const char *dir, size_t dir_len)
{
	TEE_Result res;
	struct spio_find_info f;

	res = spi_get_hod(dir, dir_len, &f.hod);
	if (res == TEE_SUCCESS) {
		f.path		= dir;
		f.path_len	= dir_len;
		f.attr_mask	= 0;	/* file and directory */
		f.attr		= 0;
		f.match_flag	= FORWARD_MATCHING;

		res = spi_find_path(&f);
	}

	return res;
}

static TEE_Result spi_find_file_and_generate_rdesc(
			const char *file, size_t file_len,
			struct spim_record_descriptor **rdesc_out)
{
	TEE_Result res;
	struct spio_find_info f;

	res = spi_get_hod_from_path(file, file_len, &f.hod);
	if (res == TEE_SUCCESS) {
		f.path		= file;
		f.path_len	= file_len;
		f.attr_mask	= SAFS_ATTR_MASK_FTYPE;
		f.attr		= SAFS_ATTR_DATA_FILE;
		f.match_flag	= PERFECT_MATCHING;

		res = spi_find_path_and_generate_rdesc(&f, rdesc_out);
	}

	return res;
}

static TEE_Result spi_find_path_and_generate_rdesc(
			const struct spio_find_info *f,
			struct spim_record_descriptor **rdesc_out)
{
	struct spim_record_descriptor *rdesc = NULL;
	TEE_Result res;
	int32_t lsector_idx = 0;
	uint32_t lrecord_offset = 0U;
	struct spif_record_info lrecord_info;

	res = spi_find_rdesc(f, &rdesc);
	if (res == TEE_SUCCESS) {
		rdesc->ref_count++;
		*rdesc_out = rdesc;
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		res = spi_search_flash_for_record_info(f, &lsector_idx,
				&lrecord_offset, &lrecord_info);

		if (res == TEE_SUCCESS) {
			rdesc = spi_alloc_rdesc(&lrecord_info.record_head,
					&lrecord_info.record_meta);
			if (rdesc != NULL) {
				rdesc->sector_idx = lsector_idx;
				rdesc->record_offset = lrecord_offset;
				*rdesc_out = rdesc;
			} else {
				res = TEE_ERROR_OUT_OF_MEMORY;
				EMSG("out of memory");
			}
		}
	} else { /* (res == TEE_ERROR_ACCESS_CONFLICT) */
		/* no operation */
	}

	return res;
}

static TEE_Result spi_find_path(const struct spio_find_info *f)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	int32_t lsector_idx = 0;
	uint32_t lrecord_offset = 0U;
	struct spif_record_info erecord_info; /* entity */
	struct spim_record_descriptor *rdesc = NULL;

	if (f->match_flag == PERFECT_MATCHING) {
		res = spi_find_rdesc(f, &rdesc);
	}
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		res = spi_search_flash_for_record_info(f, &lsector_idx,
				&lrecord_offset, &erecord_info);
	}

	return res;
}

static TEE_Result spi_search_flash_for_record_info(
			const struct spio_find_info *f,
			int32_t *search_sector_idx,
			uint32_t *search_record_offset,
			struct spif_record_info *record_info)
{
	TEE_Result res;
	TEE_Result resi = TEE_ERROR_ITEM_NOT_FOUND; /* Internal error code */
	struct spim_sector_info *sector = NULL;
	uint32_t flash_addr = 0U;
	uint32_t next_addr = 0U;
	int32_t lsector_idx;
	uint32_t first_record_offset;
	enum search_state {
		RINFO_NOT_FOUND = 1,
		RINFO_EXIST,
		RINFO_END_OF_SEARCH	/* error case */
	};
	enum search_state search_flag = RINFO_NOT_FOUND;
	uint32_t record_cnt;

	first_record_offset = *search_record_offset;
	lsector_idx = *search_sector_idx;

	for (; (lsector_idx < SAVE_SECTOR_NUM) &&
	       (search_flag == RINFO_NOT_FOUND); lsector_idx++) {
		sector = spi_get_current_sector(lsector_idx);
		flash_addr = sector->sector_addr;
		if (first_record_offset > 0U) {
			flash_addr += first_record_offset;
			first_record_offset = 0;
		}
		next_addr = flash_addr;
		record_cnt = 0U;
		while ((search_flag == RINFO_NOT_FOUND) &&
		       ((flash_addr - sector->sector_addr) <
		        sector->term_info.empty_offset)) {
			resi = spi_match_record_info(f, flash_addr,
					record_info, &next_addr);
			if (resi == TEE_SUCCESS) {
				search_flag = RINFO_EXIST;
			} else if (resi == TEE_ERROR_ITEM_NOT_FOUND) {
				/* Find the next Record Information */
				flash_addr = next_addr;
			} else if ((resi == TEE_ERROR_MAC_INVALID) &&
				   (flash_addr == next_addr)) {
				EMSG("Delete record_info num=%d sectorIdx=%d",
					sector->term_info.record_num -
					record_cnt, lsector_idx);
				sector->term_info.empty_offset = flash_addr -
						sector->sector_addr;
				sector->term_info.record_num = record_cnt;
			} else if ((resi == TEE_ERROR_MAC_INVALID) &&
				   (flash_addr < next_addr)) {
				EMSG("Skip record_info ofs=%d sectorIdx=%d",
					flash_addr - sector->sector_addr,
					lsector_idx);
				flash_addr = next_addr;
			} else {
				search_flag = RINFO_END_OF_SEARCH;
			}
			record_cnt++;
		}
		if (search_flag == RINFO_EXIST) {
			break;
		}
	}

	if (search_flag == RINFO_EXIST) {
		if (((record_info->record_head.attr & f->attr_mask) ==
		     f->attr)) {
			res = TEE_SUCCESS;
		} else {
			res = TEE_ERROR_ACCESS_CONFLICT;
			EMSG("tee file has no access rights");
		}
	} else if (search_flag == RINFO_END_OF_SEARCH) {
		flash_addr = sector->term_info.empty_offset;
		lsector_idx = SAVE_SECTOR_NUM;
		res = resi;
	} else {
		res = TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (sector != NULL) {
		*search_sector_idx = lsector_idx;
		*search_record_offset = flash_addr - sector->sector_addr;
	}

	return res;
}

static TEE_Result spi_match_record_info(const struct spio_find_info *f,
			uint32_t flash_addr,
			struct spif_record_info *record_info,
			uint32_t *next_addr)
{
	TEE_Result res;
	struct spif_record_head *lrecord_head;
	struct spif_record_meta *lrecord_meta;
	uint16_t ftype_mask;
	uint16_t filetype;

	lrecord_head = &record_info->record_head;
	lrecord_meta = &record_info->record_meta;
	ftype_mask = f->attr_mask & SAFS_ATTR_MASK_FTYPE;
	filetype = f->attr & SAFS_ATTR_MASK_FTYPE;

	/* Read the Record Head */
	res = spi_read_record_head(flash_addr, lrecord_head);

	if (res == TEE_SUCCESS) {
		flash_addr += RECORD_HEAD_SIZE;
		if (((lrecord_head->attr & ftype_mask) == filetype) &&
		    (((f->match_flag == PERFECT_MATCHING) &&
		      (f->path_len == lrecord_head->path_len)) ||
		     ((f->match_flag == FORWARD_MATCHING) &&
		      (f->path_len < lrecord_head->path_len))) &&
		    ((f->hod == lrecord_head->hod))) {

			/* Read the Record Meta */
			res = spi_read_record_meta(flash_addr, lrecord_head,
					lrecord_meta);
		} else {
			res = TEE_ERROR_ITEM_NOT_FOUND;
		}

		/* If successful the reading of Record Meta */
		if (res == TEE_SUCCESS) {
			if (strncmp(f->path, lrecord_meta->path, f->path_len)
			    == 0) {
				res = TEE_SUCCESS;
			} else {
				res = TEE_ERROR_ITEM_NOT_FOUND;
			}
		}

		flash_addr += (RECORD_META_FIXED_SIZE +
				spi_ceil_ek_size(lrecord_head->path_len));
		if (lrecord_head->data_len > 0U) {
			flash_addr += (RECORD_DATA_FIXED_SIZE +
				spi_ceil_ek_size(lrecord_head->data_len));
		}
		*next_addr = flash_addr;
	}

	return res;
}

static struct spim_sector_info *spi_get_current_sector(int32_t sector_idx)
{
	assert(sector_idx < SAVE_SECTOR_NUM);
	return &g_sector[g_current_surface[sector_idx]][sector_idx];
}

static struct spim_sector_info *spi_get_next_sector(int32_t sector_idx)
{
	int32_t next_surface;

	assert(sector_idx < SAVE_SECTOR_NUM);

	if (g_current_surface[sector_idx] == 0) {
		next_surface = 1;
	} else {
		next_surface = 0;
	}

	return &g_sector[next_surface][sector_idx];
}

static void spi_commit_sector(int32_t sector_idx,
			const struct spif_term_info *new_term_info)
{
	int32_t next_surface;

	assert(sector_idx < SAVE_SECTOR_NUM);

	if (g_current_surface[sector_idx] == 0) {
		next_surface = 1;
	} else {
		next_surface = 0;
	}
	(void)memcpy(&g_sector[next_surface][sector_idx].term_info,
		new_term_info, sizeof(struct spif_term_info));
	g_current_surface[sector_idx] = next_surface;
}

static struct spim_file_descriptor *spi_alloc_fdp(
			struct spim_record_descriptor *rdesc)
{
	struct spim_file_descriptor *fdp;
	int32_t descriptor;

	fdp = malloc(sizeof(struct spim_file_descriptor));

	if (fdp != NULL) {
		fdp->ag_rdesc = rdesc;
		descriptor = handle_get(&g_fd_handle_db, fdp);
		if (descriptor >= 0) {
			fdp->fd = descriptor;
		} else {
			free(fdp);
			fdp = NULL;
		}
	}

	return fdp;
}

static void spi_free_fdp(struct spim_file_descriptor *fdp)
{
	spi_free_rdesc(fdp->ag_rdesc);
	(void)handle_put(&g_fd_handle_db, fdp->fd);
	free(fdp);
}

static struct spim_file_descriptor *spi_get_fdp(struct tee_file_handle *fh)
{
	struct spim_file_descriptor *fdp;
	struct spim_file_descriptor *db_fdp;

	fdp = (struct spim_file_descriptor *)fh;
	db_fdp = (struct spim_file_descriptor *)handle_lookup(
			&g_fd_handle_db, fdp->fd);
	if (fdp != db_fdp) {
		fdp = NULL;	/* The file handle is invalid */
	}

	return fdp;
}

static struct spim_record_descriptor *spi_alloc_rdesc(
			const struct spif_record_head *record_head,
			const struct spif_record_meta *record_meta)
{
	struct spim_record_descriptor *rdesc;
	int32_t descriptor;
	void *buf;

	rdesc = malloc(sizeof(struct spim_record_descriptor));

	if (rdesc != NULL) {
		(void)memset(rdesc, 0, sizeof(struct spim_record_descriptor));
		if (record_head != NULL) {
			(void)memcpy(&rdesc->record_info.record_head,
				record_head, sizeof(struct spif_record_head));
		}
		if (record_meta != NULL) {
			(void)memcpy(&rdesc->record_info.record_meta,
				record_meta, sizeof(struct spif_record_meta));
		}
		buf = (void *)g_record_data_buf;
		rdesc->record_info.record_data = (struct spif_record_data *)buf;
		rdesc->sector_idx = RDESC_SECTOR_IDX_UNASSIGNED;
		rdesc->record_offset = 0;
		rdesc->ref_count = 1;
		rdesc->ctrl_flag = 0;
		descriptor = handle_get(&g_rd_handle_db, rdesc);
		if (descriptor >= 0) {
			rdesc->rd = descriptor;
		} else {
			free(rdesc);
			rdesc = NULL;
		}
	}

	return rdesc;
}

static void spi_free_rdesc(struct spim_record_descriptor *rdesc)
{
	TEE_Result res;

	rdesc->ref_count--;

	if (rdesc->ref_count == 0) {
		if ((rdesc->ctrl_flag & RDESC_CTRL_UNLINK) != 0) {
			res = spi_delete_record_info(rdesc);
			if (res == TEE_SUCCESS) {
				DMSG("tee file unlink success.");
			} else {
				EMSG("tee file unlink failure. r=0x%x", res);
			}
		}
		(void)handle_put(&g_rd_handle_db, rdesc->rd);
		free(rdesc);
		if (rdesc == g_record_data_rdesc) {
			g_record_data_rdesc = NULL;
		}
	}
}

static struct spim_record_descriptor *spi_get_rdesc(int32_t rd)
{
	return (struct spim_record_descriptor *)handle_lookup(
			&g_rd_handle_db, rd);
}

static TEE_Result spi_find_rdesc(const struct spio_find_info *f,
			struct spim_record_descriptor **rdesc_out)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	struct spim_record_descriptor *rdesc;
	struct spif_record_head *lrecord_head;
	struct spif_record_meta *lrecord_meta;
	int32_t i;
	int32_t cmpret;
	int32_t exist_flag = 0;

	for (i = 0; i < (int32_t)g_rd_handle_db.max_ptrs; i++) {
		rdesc = spi_get_rdesc(i);
		if (rdesc != NULL) {
			lrecord_head = &rdesc->record_info.record_head;
			lrecord_meta = &rdesc->record_info.record_meta;
			if (((rdesc->ctrl_flag & RDESC_CTRL_DIRSTREAM) == 0) &&
			    (f->path_len == lrecord_head->path_len) &&
			    (f->hod == lrecord_head->hod)) {
				cmpret = strcmp(f->path, lrecord_meta->path);
				if (cmpret == 0) {
					/* Record Information is found */
					exist_flag = 1;
					break;
				}
			}
		}
	}

	if (exist_flag == 1) {
		if ((lrecord_head->attr & f->attr_mask) == f->attr) {
			*rdesc_out = rdesc;
			res = TEE_SUCCESS;
		} else {
			res = TEE_ERROR_ACCESS_CONFLICT;
			EMSG("record has no access rights");
		}
	}

	return res;
}

static void spi_update_rdesc(const struct spim_record_descriptor *update_rdesc,
			int32_t difference, uint32_t update_size)
{
	int32_t lsector_idx;
	uint32_t lrecord_offset;
	int32_t i;
	struct spim_record_descriptor *rdesc;
	const struct spif_record_head *new_head;
	struct spif_record_head *cur_h;

	lsector_idx = update_rdesc->sector_idx;
	lrecord_offset = update_rdesc->record_offset;
	new_head = &update_rdesc->record_info.record_head;

	for (i = 0; i < (int32_t)g_rd_handle_db.max_ptrs; i++) {
		rdesc = spi_get_rdesc(i);
		if ((rdesc != NULL) &&
		    (rdesc->sector_idx == lsector_idx)) {
			if (lrecord_offset < rdesc->record_offset) {
				rdesc->record_offset += difference;
			} else if (((rdesc->ctrl_flag & RDESC_CTRL_DIRSTREAM)
			  != 0) && (lrecord_offset == rdesc->record_offset)) {
				if (update_size == 0) {
					/* delete the record info */
					rdesc->ctrl_flag |= RDESC_CTRL_DELETE;
				} else {
					/* update the record info size */
					cur_h = &rdesc->record_info.record_head;
					cur_h->path_len = new_head->path_len;
					cur_h->data_len = new_head->data_len;
				}
			} else {
				/* no operation */
			}
		}
	}
}

static struct tee_fs_dir *spi_alloc_dirst(const char *dir, size_t dir_len)
{
	struct tee_fs_dir *dirst;
	struct spim_record_descriptor *rdesc;
	TEE_Result res;

	dirst = malloc(sizeof(struct tee_fs_dir));
	if (dirst != NULL) {
		(void)memset(dirst, 0, sizeof(struct tee_fs_dir));
		(void)memcpy(dirst->dir, dir, dir_len);
		dirst->finfo.path = dirst->dir;
		dirst->finfo.path_len	= dir_len;
		dirst->finfo.attr_mask	= 0;	/* file and directory */
		dirst->finfo.attr	= 0;
		dirst->finfo.match_flag	= FORWARD_MATCHING;

		res = spi_get_hod(dir, dir_len, &dirst->finfo.hod);
		if (res == TEE_SUCCESS) {
			/* rdesc of the Directory Stream */
			rdesc = spi_alloc_rdesc(NULL, NULL);
			if (rdesc != NULL) {
				rdesc->ctrl_flag |= RDESC_CTRL_DIRSTREAM;
				dirst->search_rdesc = rdesc;
			} else {
				free(dirst);
				dirst = NULL;
			}
		} else {
			free(dirst);
			dirst = NULL;
		}
	}

	return dirst;
}

static void spi_free_dirst(struct tee_fs_dir *dirst)
{
	spi_free_rdesc(dirst->search_rdesc);
	free(dirst);
}

static TEE_Result spi_read_flash(uint32_t flash_addr, uint8_t *buf,
			size_t rsize)
{
	TEE_Result res;
	uint32_t ret;

	ret = qspi_hyper_flash_read(flash_addr, buf, rsize);

	if (ret == FL_DRV_OK) {
		res = TEE_SUCCESS;
	} else {
		res = TEE_ERROR_TARGET_DEAD;
	}

	return res;
}

static TEE_Result spi_erase_and_write_sector(uint32_t sector_addr,
			const uint8_t *encrypted_record_buf,
			uint32_t record_buf_size,
			const uint8_t *encrypted_term_info)
{
	TEE_Result res;
	uint32_t ret;

	ret = qspi_hyper_flash_erase(sector_addr);
	if (ret == FL_DRV_OK) {
		if (encrypted_record_buf != NULL) {
			ret = qspi_hyper_flash_write(sector_addr,
					encrypted_record_buf,
					record_buf_size);
		}
		if (ret == FL_DRV_OK) {
			ret = qspi_hyper_flash_write(
					sector_addr + TERM_INFO_OFFSET,
					encrypted_term_info,
					TERM_INFO_SIZE);
		}
		if (ret == FL_DRV_OK) {
			res = TEE_SUCCESS;
		} else {
			res = TEE_ERROR_TARGET_DEAD;
		}
	} else {
		res = TEE_ERROR_TARGET_DEAD;
	}

	return res;
}

static TEE_Result tee_standalone_open(const char *file, size_t file_len,
			size_t *file_size, struct tee_file_handle **fh_out)
{
	TEE_Result res;
	struct spim_record_descriptor *rdesc = NULL;
	struct spim_file_descriptor *fdp;

	res = spi_find_file_and_generate_rdesc(file, file_len, &rdesc);
	if (rdesc != NULL) {
		fdp = spi_alloc_fdp(rdesc);
		if (fdp != NULL) {
			*file_size = rdesc->record_info.record_head.data_len;
			*fh_out = (struct tee_file_handle *)fdp;
			res = TEE_SUCCESS;
		} else {
			spi_free_rdesc(rdesc);
			res = TEE_ERROR_OUT_OF_MEMORY;
		}
	}

	return res;
}

static TEE_Result tee_standalone_create(const char *file, size_t file_len,
			const struct spio_write_data *wd, size_t wd_num,
			bool overwrite, struct tee_file_handle **fh_out)
{
	TEE_Result res;
	struct spim_record_descriptor *rdesc = NULL;
	struct spim_file_descriptor *fdp;
	uint16_t lattr = SAFS_ATTR_DATA_FILE;
	uint32_t old_size;

	res = spi_find_file_and_generate_rdesc(file, file_len, &rdesc);
	if (rdesc != NULL) {
		if (overwrite) {
			old_size = spi_get_record_info_size(rdesc);
			spi_write_record_data(&rdesc->record_info, wd, wd_num);
			res = spi_update_record_info(rdesc, old_size);
			if (res != TEE_SUCCESS) {
				spi_free_rdesc(rdesc);
				EMSG("tee file update failure");
			}
		} else {
			spi_free_rdesc(rdesc);
			res = TEE_ERROR_ACCESS_CONFLICT;
			EMSG("tee file already exists");
		}
	} else {
		lattr |= SAFS_ATTR_DATA_IRUSR | SAFS_ATTR_DATA_IWUSR;
		rdesc = spi_create_record_info(file, file_len, lattr, 
				wd, wd_num, &res);
		if (rdesc == NULL) {
			EMSG("tee file create failure");
		}
	}

	if (res == TEE_SUCCESS) {
		fdp = spi_alloc_fdp(rdesc);
		if (fdp != NULL) {
			*fh_out = (struct tee_file_handle *)fdp;
		} else {
			spi_free_rdesc(rdesc);
			res = TEE_ERROR_OUT_OF_MEMORY;
		}
	}

	return res;
}

static void tee_standalone_close(struct spim_file_descriptor *fdp)
{
	spi_free_fdp(fdp);
}

static TEE_Result tee_standalone_read(struct spim_file_descriptor *fdp,
			void *buf, size_t *buf_len, size_t fpos)
{
	TEE_Result res;
	struct spim_record_descriptor *rdesc;
	struct spif_record_data *lrecord_data;
	uint32_t rdata_len;
	size_t read_len;

	rdesc = fdp->ag_rdesc;
	lrecord_data = rdesc->record_info.record_data;
	res = spi_read_record_data(rdesc);
	if (res == TEE_SUCCESS) {
		read_len = *buf_len;
		rdata_len = rdesc->record_info.record_head.data_len;
		if (rdata_len < (fpos + read_len)) {
			if (fpos < rdata_len) {
				read_len = rdata_len - fpos;
			} else {
				read_len = 0;
			}
			DMSG("reached EOF, update read length to %zu",
				read_len);
		}
		if (read_len > 0U) {
			(void)memcpy(buf, &lrecord_data->data[fpos], read_len);
		}
		*buf_len = read_len;
	} else if (res == TEE_ERROR_NO_DATA) {
		*buf_len = 0;
		DMSG("no data, read length to 0");
	} else {
		EMSG("record data read error!");
	}

	return res;
}

static TEE_Result tee_standalone_write(struct spim_file_descriptor *fdp,
			const void *buf, size_t buf_len, size_t fpos)
{
	TEE_Result res;
	struct spim_record_descriptor *rdesc;
	struct spif_record_head *lrecord_head;
	struct spif_record_data *lrecord_data;
	uint32_t old_size;
	uint32_t old_data_len;
	uint32_t new_data_len;
	uint32_t new_fpos;

	rdesc = fdp->ag_rdesc;
	lrecord_head = &rdesc->record_info.record_head;
	lrecord_data = rdesc->record_info.record_data;
	old_size = spi_get_record_info_size(rdesc);
	old_data_len = lrecord_head->data_len;
	new_fpos = fpos + buf_len;
	if (new_fpos < old_data_len) {
		new_data_len = old_data_len;
	} else {
		new_data_len = new_fpos;
	}
	if (old_data_len > 0U) {
		res = spi_read_record_data(rdesc);
		g_record_data_rdesc = NULL;
	} else {
		res = TEE_SUCCESS;
	}
	if ((res == TEE_SUCCESS) && (old_data_len < new_data_len)) {
		res = spi_check_sector_range(rdesc,
			0U, new_data_len - old_data_len);
	}
	if (res == TEE_SUCCESS) {
		if (old_data_len < fpos) {
			/* hole area */
			(void)memset(&lrecord_data->data[old_data_len],
				0, fpos - old_data_len);
		}
		(void)memcpy(&lrecord_data->data[fpos], buf, buf_len);
		lrecord_head->data_len = new_data_len;

		res = spi_update_record_info(rdesc, old_size);
		if (res != TEE_SUCCESS) {
			/* rollback */
			lrecord_head->data_len = old_data_len;
		}
	}

	return res;
}

static TEE_Result tee_standalone_rename(const char *old_file, size_t old_len,
			const char *new_file, size_t new_len, bool overwrite)
{
	TEE_Result res;
	struct spim_record_descriptor *rdesc = NULL;
	struct spif_record_info *lrecord_info;
	uint32_t old_size;

	res = spi_find_file_and_generate_rdesc(old_file, old_len, &rdesc);
	if (rdesc != NULL) {
		res = spi_find_file(new_file, new_len);
		if (res == TEE_SUCCESS) {
			if (overwrite) {
				res = TEE_ERROR_NOT_SUPPORTED;
				EMSG("overwrite is not supported");
			} else {
				res = TEE_ERROR_ACCESS_CONFLICT;
				EMSG("new file exists");
			}
		} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
			/* Normal case */
			res = TEE_SUCCESS;
		} else {
			EMSG("find file error!");
		}
		if ((res == TEE_SUCCESS) && (old_len < new_len)) {
			res = spi_check_sector_range(rdesc,
				new_len - old_len, 0U);
		}

		if (res == TEE_SUCCESS) {
			lrecord_info = &rdesc->record_info;
			old_size = spi_get_record_info_size(rdesc);
			if (lrecord_info->record_head.data_len > 0U) {
				res = spi_read_record_data(rdesc);
			}
		}
		if (res == TEE_SUCCESS) {
			lrecord_info->record_head.path_len = new_len;
			(void)memcpy(lrecord_info->record_meta.path,
				new_file, new_len + 1);

			res = spi_update_record_info(rdesc, old_size);
			if (res != TEE_SUCCESS) {
				/* rollback */
				lrecord_info->record_head.path_len = old_len;
				(void)memcpy(lrecord_info->record_meta.path,
					old_file, old_len + 1);
			}
		}
		spi_free_rdesc(rdesc);
	}

	return res;
}

static TEE_Result tee_standalone_remove(const char *file, size_t file_len)
{
	TEE_Result res;
	struct spim_record_descriptor *rdesc = NULL;

	res = spi_find_file_and_generate_rdesc(file, file_len, &rdesc);
	if (rdesc != NULL) {
		rdesc->ctrl_flag |= RDESC_CTRL_UNLINK;
		spi_free_rdesc(rdesc);
		res = TEE_SUCCESS;
	}

	return res;
}

static TEE_Result tee_standalone_truncate(struct spim_file_descriptor *fdp,
			size_t length)
{
	TEE_Result res;
	struct spim_record_descriptor *rdesc;
	struct spif_record_head *lrecord_head;
	struct spif_record_data *lrecord_data;
	uint32_t old_size;
	uint32_t old_dlen;

	rdesc = fdp->ag_rdesc;
	lrecord_head = &rdesc->record_info.record_head;
	lrecord_data = rdesc->record_info.record_data;
	if (length != lrecord_head->data_len) {
		old_size = spi_get_record_info_size(rdesc);
		old_dlen = lrecord_head->data_len;
		if (length > 0U) {
			if (old_dlen > 0U) {
				res = spi_read_record_data(rdesc);
				g_record_data_rdesc = NULL;
			} else {
				res = TEE_SUCCESS;
			}
			if ((res == TEE_SUCCESS) &&
			    (old_dlen < length)) {
				res = spi_check_sector_range(rdesc,
					0U, length - old_dlen);
				if (res == TEE_SUCCESS) {
					/* hole area */
					(void)memset(&lrecord_data->
						data[old_dlen],
						0, length - old_dlen);
				}
			}
		} else {
			res = TEE_SUCCESS;
		}
		if (res == TEE_SUCCESS) {
			lrecord_head->data_len = length;

			res = spi_update_record_info(rdesc, old_size);
			if (res != TEE_SUCCESS) {
				/* rollback */
				lrecord_head->data_len = old_dlen;
			}
		}
	} else {
		/* no operation */
		res = TEE_SUCCESS;
	}

	return res;
}

static TEE_Result tee_standalone_opendir(const char *name,
			size_t name_len, struct tee_fs_dir **dirst_out)
{
	TEE_Result res;
	struct tee_fs_dir *dirst;

	res = spi_find_file_under_dir(name, name_len);
	if (res == TEE_SUCCESS) {
		dirst = spi_alloc_dirst(name, name_len);
		if (dirst != NULL) {
			*dirst_out = dirst;
		} else {
			res = TEE_ERROR_OUT_OF_MEMORY;
			EMSG("out of memory");
		}
	}

	return res;
}

static TEE_Result tee_standalone_readdir(struct tee_fs_dir *dirst,
			struct tee_fs_dirent **dirent_out)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
	struct spim_record_descriptor *rdesc;
	const char *filename;
	size_t filename_len;

	rdesc = dirst->search_rdesc;

	while ((rdesc->sector_idx < SAVE_SECTOR_NUM) && (res != TEE_SUCCESS)) {
		if (rdesc->sector_idx == RDESC_SECTOR_IDX_UNASSIGNED) {
			rdesc->sector_idx = 0;
		} else if ((rdesc->ctrl_flag & RDESC_CTRL_DELETE) == 0) {
			rdesc->record_offset += spi_get_record_info_size(rdesc);
		} else {
			rdesc->ctrl_flag &= ~RDESC_CTRL_DELETE;
		}

		res = spi_search_flash_for_record_info(&dirst->finfo,
				&rdesc->sector_idx, &rdesc->record_offset,
				&rdesc->record_info);

		if (res == TEE_SUCCESS) {
			spi_get_filename(rdesc->record_info.record_meta.path,
					rdesc->record_info.record_head.path_len,
					&filename);
			filename_len = strlen(filename);
			dirst->dirent.oidlen = tee_hs2b((uint8_t *)filename,
					dirst->dirent.oid, filename_len,
					filename_len / 2U);
			*dirent_out = &dirst->dirent;
			DMSG("oid=%s", filename);
		}
	}

	return res;
}

static void tee_standalone_closedir(struct tee_fs_dir *dirst)
{
	spi_free_dirst(dirst);
}

static TEE_Result standalone_fs_open(struct tee_pobj *po, size_t *size,
			struct tee_file_handle **fh)
{
	TEE_Result res;
	char *file;
	size_t len;

	DMSG("IN  po=%p, size=%p, fh=%p", (void *)po, (void *)size, (void *)fh);

	if ((po != NULL) && (size != NULL) && (fh != NULL)) {
		res = spi_get_status_and_alloc_file(po, &file, &len);
		if (res == TEE_SUCCESS) {
			spi_lock();
			res = tee_standalone_open(file, len, size, fh);
			spi_unlock();
			spi_free_file(file);
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT res=0x%X, *fh=%p, *size=%zu", res,
		(res == 0U) ? (void *)*fh : NULL, (res == 0U) ? *size : 0U);
	return res;
}

static TEE_Result standalone_fs_create(struct tee_pobj *po, bool overwrite,
			const void *head, size_t head_size,
			const void *attr, size_t attr_size,
			const void *data, size_t data_size,
			struct tee_file_handle **fh)
{
	TEE_Result res;
	char *file;
	size_t len;
	struct spio_write_data wd[3];
	const size_t wd_num = sizeof(wd) / sizeof(struct spio_write_data);

	DMSG("IN  po=%p, overw=%d, head=%p,%zu, attr=%p,%zu, data=%p,%zu, fh=%p"
		, (void *)po, overwrite, head, head_size, attr, attr_size,
		data, data_size, (void *)fh);

	if ((po != NULL) && (fh != NULL)) {
		res = spi_get_status_and_alloc_file(po, &file, &len);
		if (res == TEE_SUCCESS) {
			wd[0].data = head;
			wd[0].size = head_size;
			wd[1].data = attr;
			wd[1].size = attr_size;
			wd[2].data = data;
			wd[2].size = data_size;
			spi_lock();
			res = tee_standalone_create(file, len, wd,
					wd_num, overwrite, fh);
			spi_unlock();
			spi_free_file(file);
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT res=0x%X, *fh=%p", res, (res == 0U) ? (void *)*fh : NULL);
	return res;
}

static void standalone_fs_close(struct tee_file_handle **fh)
{
	TEE_Result res = TEE_SUCCESS;
	struct spim_file_descriptor *fdp;

	DMSG("IN  fh=%p", (fh != NULL) ? (void *)*fh : NULL);

	if ((fh != NULL) && (*fh != NULL)) {
		res = spi_get_status();
		if (res == TEE_SUCCESS) {
			spi_lock();
			fdp = spi_get_fdp(*fh);
			if (fdp != NULL) {
				tee_standalone_close(fdp);
				*fh = NULL;
			} else {
				EMSG("Invalid file descriptor.");
			}
			spi_unlock();
		}
	} else {
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT status=0x%X", res);
}

static TEE_Result standalone_fs_read(struct tee_file_handle *fh, size_t pos,
			void *buf, size_t *len)
{
	TEE_Result res;
	struct spim_file_descriptor *fdp;

	DMSG("IN  fh=%p, pos=%zu, buf=%p, len=%zu", (void *)fh, pos, buf,
		(len != NULL) ? *len : 0U);

	if ((fh != NULL) && (buf != NULL) && (len != NULL)) {
		res = spi_get_status();
		if (res == TEE_SUCCESS) {
			spi_lock();
			fdp = spi_get_fdp(fh);
			if (fdp != NULL) {
				res = tee_standalone_read(fdp, buf, len, pos);
			} else {
				res = TEE_ERROR_BAD_PARAMETERS;
				EMSG("Invalid file descriptor.");
			}
			spi_unlock();
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT res=0x%X, *len=%zu", res, (res == 0U) ? *len : 0U);
	return res;
}

static TEE_Result standalone_fs_write(struct tee_file_handle *fh, size_t pos,
			const void *buf, size_t len)
{
	TEE_Result res;
	struct spim_file_descriptor *fdp;

	DMSG("IN  fh=%p, pos=%zu, buf=%p, len=%zu", (void *)fh, pos, buf, len);

	if ((fh != NULL) && ((len == 0U) || (buf != NULL))) {
		res = spi_get_status();
		if (res == TEE_SUCCESS) {
			spi_lock();
			fdp = spi_get_fdp(fh);
			if (fdp != NULL) {
				if (len > 0U) {
					res = tee_standalone_write(fdp, buf,
							len, pos);
				} else {
					res = TEE_SUCCESS;
				}
			} else {
				res = TEE_ERROR_BAD_PARAMETERS;
				EMSG("Invalid file descriptor.");
			}
			spi_unlock();
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT res=0x%X", res);
	return res;
}

static TEE_Result standalone_fs_rename(struct tee_pobj *old_po,
			struct tee_pobj *new_po, bool overwrite)
{
	TEE_Result res;
	char *old_file;
	size_t old_len;
	char *new_file;
	size_t new_len;

	DMSG("IN  old_po=%p, new_po=%p, overwrite=%d", (void *)old_po,
		(void *)new_po, overwrite);

	if ((old_po != NULL) && (new_po != NULL)) {
		res = spi_get_status_and_alloc_file(old_po, &old_file,
					&old_len);
		if (res == TEE_SUCCESS) {
			res = spi_alloc_file(new_po, &new_file, &new_len);
			if (res == TEE_SUCCESS) {
				spi_lock();
				res = tee_standalone_rename(old_file, old_len,
						new_file, new_len, overwrite);
				spi_unlock();
				spi_free_file(new_file);
			}
			spi_free_file(old_file);
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT res=0x%X", res);
	return res;
}

static TEE_Result standalone_fs_remove(struct tee_pobj *po)
{
	TEE_Result res;
	char *file;
	size_t len;

	DMSG("IN  po=%p", (void *)po);

	if (po != NULL) {
		res = spi_get_status_and_alloc_file(po, &file, &len);
		if (res == TEE_SUCCESS) {
			spi_lock();
			res = tee_standalone_remove(file, len);
			spi_unlock();
			spi_free_file(file);
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT res=0x%X", res);
	return res;
}

static TEE_Result standalone_fs_truncate(struct tee_file_handle *fh,
			size_t size)
{
	TEE_Result res;
	struct spim_file_descriptor *fdp;

	DMSG("IN  fh=%p, size=%zu", (void *)fh, size);

	if (fh != NULL) {
		res = spi_get_status();
		if (res == TEE_SUCCESS) {
			spi_lock();
			fdp = spi_get_fdp(fh);
			if (fdp != NULL) {
				res = tee_standalone_truncate(fdp, size);
			} else {
				res = TEE_ERROR_BAD_PARAMETERS;
				EMSG("Invalid file descriptor.");
			}
			spi_unlock();
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT res=0x%X", res);
	return res;
}

static TEE_Result standalone_fs_opendir(const TEE_UUID *uuid,
			struct tee_fs_dir **d)
{
	TEE_Result res;
	char *name = NULL;
	size_t len = 0;

	DMSG("IN  uuid=%p, d=%p", (const void *)uuid, (void *)d);

	if ((uuid != NULL) && (d != NULL)) {
		res = spi_get_status_and_alloc_dir(uuid, &name, &len);
		if (res == TEE_SUCCESS) {
			spi_lock();
			res = tee_standalone_opendir(name, len, d);
			spi_unlock();
			spi_free_file(name);
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT res=0x%X, *d=%p", res, (d != NULL) ? (void *)*d : NULL);
	return res;
}

static TEE_Result standalone_fs_readdir(struct tee_fs_dir *d,
			struct tee_fs_dirent **ent)
{
	TEE_Result res;

	DMSG("IN  d=%p, ent=%p", (void *)d, (void *)ent);

	if ((d != NULL) && (ent != NULL)) {
		res = spi_get_status();
		if (res == TEE_SUCCESS) {
			spi_lock();
			res = tee_standalone_readdir(d, ent);
			spi_unlock();
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT res=0x%X, oidlen=%zu", res,
		(res == 0U) ? (*ent)->oidlen : 0U);
	return res;
}

static void standalone_fs_closedir(struct tee_fs_dir *d)
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("IN  d=%p", (void *)d);

	if (d != NULL) {
		res = spi_get_status();
		if (res == TEE_SUCCESS) {
			spi_lock();
			tee_standalone_closedir(d);
			spi_unlock();
		}
	} else {
		EMSG("Invalid argument provided.");
	}

	DMSG("OUT status=0x%X", res);
}

const struct tee_file_operations standalone_fs_ops = {
	.open = standalone_fs_open,
	.create = standalone_fs_create,
	.close = standalone_fs_close,
	.read = standalone_fs_read,
	.write = standalone_fs_write,
	.truncate = standalone_fs_truncate,
	.rename = standalone_fs_rename,
	.remove = standalone_fs_remove,
	.opendir = standalone_fs_opendir,
	.readdir = standalone_fs_readdir,
	.closedir = standalone_fs_closedir
};
