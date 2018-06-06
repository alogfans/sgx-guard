#ifndef GUARD_ENCLAVE_H
#define GUARD_ENCLAVE_H

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif

    int encalve_init_ra(int b_pse, uint32_t *context);
    int encalve_close_ra(uint32_t context);

#if defined(__cplusplus)
}
#endif

#endif // GUARD_ENCLAVE_H
