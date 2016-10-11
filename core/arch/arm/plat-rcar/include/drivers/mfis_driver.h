/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
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

#ifndef MFIS_DRIVER_H_
#define MFIS_DRIVER_H_

#define	MFIS_ERR_DET_MAX	(8U)

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
