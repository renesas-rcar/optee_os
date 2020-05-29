/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2017, Renesas Electronics Corporation
 */

#ifndef MFIS_DRIVER_H_
#define MFIS_DRIVER_H_

#define	MFIS_ERR_DET_MAX	(2U)

#define	MFIS_SUCCESS			(0)
#define	MFIS_ERR_PARAMETER		(-1)
#define	MFIS_ERR_SEQUENCE		(-2)

typedef struct {
	uint32_t	control[MFIS_ERR_DET_MAX];	/* MFIERRxxxRy */
	uint32_t	target[MFIS_ERR_DET_MAX];
}MFIS_ERR_SETTING_T;

typedef struct {
	uint32_t	error[MFIS_ERR_DET_MAX];
}MFIS_ERR_FACTOR_T;

int32_t mfis_error_detection_start(MFIS_ERR_SETTING_T *err,
		void (*cb)(MFIS_ERR_FACTOR_T*));
int32_t mfis_error_detection_stop(void);

#endif /* MFIS_DRIVER_H_ */
