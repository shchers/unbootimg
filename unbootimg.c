/* tools/mkbootimg/unbootimg.c
**
** Copyright 2011, Sergey Shcherbakov <shchers@gmail.com>
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <bootimg.h>
#include <mincrypt/sha.h>

#define NAME_KERNEL     "zImage"
#define NAME_RAMDISK    "ramdisk.img.gz"
#define NAME_SECOND     "second.img.gz"
#define NAME_PARAMS     "params.txt"

/**
* Saving file to disk
*
* @param[in]    fn      Output filename
*
* @param[in]    ptr     Pointer to file content
*
* @param[in]    size    File size
*
* @return Error code
*/
static int save_file(const char *fn, unsigned char *ptr, unsigned size)
{
    int fd = open(fn, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(fd < 0) {
        fprintf(stderr,"ERROR: could not create '%s'\n", fn);
        return 0;
    }

    if(write(fd, ptr, size) == -1) {
        close(fd);
        unlink(fn);
        fprintf(stderr,"ERROR: failed writing '%s': %s\n", fn,
                strerror(errno));
        return errno;
    }

    close(fd);
    return 0;
}

/**
* Saving parameters to disk
*
* @param[in]    fn      Output filename
*
* @param[in]    pHeader Pointer to boot image header
*
* @return Error code
*/
static int save_header(const char *lpszFilename, boot_img_hdr *pHeader)
{
    int nIndex;
    FILE *fp = fopen(lpszFilename, "w");
    if(fp == NULL) {
        fprintf(stderr,"ERROR: file \"%s\" could not create\n", lpszFilename);
        return errno;
    }

    if (fprintf(fp, "magic        = \"") < 0)
        goto failed;
    for ( nIndex = 0; nIndex < BOOT_MAGIC_SIZE; nIndex++ ){
        if ( ! pHeader->magic[nIndex] )
            break;

        if ( fputc(pHeader->magic[nIndex], fp) != pHeader->magic[nIndex] )
            goto failed;
    }
    if (fprintf(fp, "\"\n") < 0 )
        goto failed;

    if (fprintf(fp, "kernel_size  = %d\n", pHeader->kernel_size) < 0)
        goto failed;
    if (fprintf(fp, "kernel_addr  = 0x%.8X\n", pHeader->kernel_addr) < 0)
        goto failed;
    if (fprintf(fp, "ramdisk_size = %d\n", pHeader->ramdisk_size) < 0)
        goto failed;
    if (fprintf(fp, "ramdisk_addr = 0x%.8X\n", pHeader->ramdisk_addr) < 0)
        goto failed;
    if (fprintf(fp, "second_size  = %d\n", pHeader->second_size) < 0)
        goto failed;
    if (fprintf(fp, "second_addr  = 0x%.8X\n", pHeader->second_addr) < 0)
        goto failed;
    if (fprintf(fp, "tags_addr    = 0x%.8X\n", pHeader->tags_addr) < 0)
        goto failed;
    if (fprintf(fp, "page_size    = %d\n", pHeader->page_size) < 0)
        goto failed;
    if (fprintf(fp, "name         = \"") < 0)
        goto failed;
    for ( nIndex = 0; nIndex < BOOT_NAME_SIZE; nIndex++ ){
        if ( ! pHeader->name[nIndex] )
            break;

        if ( fputc(pHeader->name[nIndex], fp) != pHeader->name[nIndex] )
            goto failed;
    }
    if (fprintf(fp, "\"\n") < 0 )
        goto failed;
    if (fprintf(fp, "cmdline      = \"") < 0)
        goto failed;
    for ( nIndex = 0; nIndex < BOOT_ARGS_SIZE; nIndex++ ){
        if ( ! pHeader->cmdline[nIndex] )
            break;

        if ( fputc(pHeader->cmdline[nIndex], fp) != pHeader->cmdline[nIndex] )
            goto failed;
    }
    if (fprintf(fp, "\"\n") < 0 )
        goto failed;
    if (fprintf(fp, "id           = \"") < 0)
        goto failed;
    for ( nIndex = 0; nIndex < 8; nIndex++ ){
        if ( fprintf(fp, "%X", pHeader->cmdline[nIndex]) < 0 )
            goto failed;
    }
    if (fprintf(fp, "\"\n") < 0 )
        goto failed;

    fclose(fp);
    return 0;

failed:
    fclose(fp);
    unlink(lpszFilename);
    fprintf(stderr,"ERROR: failed writing '%s': %s\n", lpszFilename,
            strerror(errno));
    return errno;
}

int usage(void)
{
    fprintf(stderr,"usage: unbootimg\n"
            "       --input|-i <filename>\n"
            "       --kernel|-k <filename, default is \"" NAME_KERNEL "\">\n"
            "       --ramdisk|-r <filename, default is \"" NAME_RAMDISK "\">\n"
            "       --second|-s <filename, default is \"" NAME_SECOND "\">\n"
            "       --params|-p <filename, default is \"" NAME_PARAMS "\">\n"
            );
    return 1;
}

int skip_padding(int fd, unsigned nPageSize, unsigned nItemSize){
    unsigned nPageMask = nPageSize - 1;
    unsigned nCount = nPageSize - (nItemSize & nPageMask);

    printf("DEBUG: item size %d, so will be skipped %d bytes\n", nItemSize, nCount);
    
    if ((nItemSize & nPageMask) == 0)
        return 0;

    if(lseek(fd, nCount, SEEK_CUR) == -1) {
        fprintf(stderr, "ERROR: skipping %d bytes failed with errro [%d]:\"%s\"",
                nCount, errno, strerror(errno));
        return 1;
    }
    else
        return 0;
}

int extract_image(int fd, unsigned size, unsigned page_size, const char *lpcszFilename, SHA_CTX *pShaCtx)
{
    unsigned char *pData = NULL;

    if ( ! size ) {
        fprintf(stderr, "WARNING: file \"%s\" will not be created due to zero size\n", lpcszFilename);
        // Updating SHA-1 context with dummy data
        SHA_update(pShaCtx, NULL, 0);
        SHA_update(pShaCtx, &size, sizeof(size));
        return 0;
    }

    pData = (unsigned char*)malloc(size);
    if (pData == NULL) {
        fprintf(stderr,"ERROR: allocating %d of memory failed with error [%d]:\"%s\"\n",
                size, errno, strerror(errno));
        return 1;
    }

    if(read(fd, pData, size) != (int)size){
        fprintf(stderr, "ERROR: reading image from file failed");
        free(pData);
        return 1;
    }

    SHA_update(pShaCtx, pData, size);
    SHA_update(pShaCtx, &size, sizeof(size));

    if ( save_file(lpcszFilename, pData, size) ){
        free(pData);
        return 1;
    }

    free(pData);

    // Skipping padding
    if ( skip_padding(fd, page_size, size) ) {
        fprintf(stderr, "ERROR: reading image from file failed");
        return 1;
    }

    return 0;
}

int main(int argc, const char **argv)
{
    // Boot image header descriptor
    boot_img_hdr Header;
    int nFileSize = -1;
    int nHdrSize = -1;
    // File descriptor
    int fd = -1;
    // Pointer to data
    unsigned char *pData = NULL;
    // Filename of input boot image
    const char *lpcszBootimg = NULL;
    // Filename of output kernel image
    const char *lpcszKernel = NAME_KERNEL;
    // Filename of output ramdisk image
    const char *lpcszRamdisk = NAME_RAMDISK;
    // Filename of output second image
    const char *lpcszSecond= NAME_SECOND;
    // Filename of output parameters descriptor
    const char *lpcszParams = NAME_PARAMS;
    // SHA-1 context
    SHA_CTX ctx;
    uint8_t* sha;

    memset(&Header, 0, sizeof(Header));
    
    argc--;
    argv++;

    // Reading input arguments
    while(argc > 0){
        const char *arg = argv[0];
        const char *val = argv[1];
        if(argc < 2) {
            return usage();
        }
        argc -= 2;
        argv += 2;
        if(!strcmp(arg, "--input") || !strcmp(arg, "-i")) {
            lpcszBootimg = val;
        } else if(!strcmp(arg, "--kernel") || !strcmp(arg, "-k")) {
            lpcszKernel = val;
        } else if(!strcmp(arg, "--ramdisk") || !strcmp(arg, "-r")) {
            lpcszRamdisk = val;
        } else if(!strcmp(arg, "--second") || !strcmp(arg, "-s")) {
            lpcszSecond = val;
        } else if(!strcmp(arg, "--params") || !strcmp(arg, "-p")) {
            lpcszParams = val;
        } else {
            return usage();
        }
    }

    if ( lpcszBootimg == NULL ){
        fprintf(stderr,"ERROR: no boot image specified\n");
        return usage();
    }

    fd = open(lpcszBootimg, O_RDONLY);
    if(fd < 0){
        fprintf(stderr,"ERROR: boot image \"%s\" could not be opened\n", lpcszBootimg);
        return usage();
    }

    nFileSize = lseek(fd, 0, SEEK_END);
    if((nFileSize < 0) || (lseek(fd, 0, SEEK_SET) != 0)) {
        fprintf(stderr,"ERROR: seeking boot image \"%s\" failed\n", lpcszBootimg);
        goto oops;
    }

    printf("INFO: Boot image \"%s\" size = %d bytes\n", lpcszBootimg, nFileSize);

    if(read(fd, &Header, sizeof(Header)) != sizeof(Header)){
        fprintf(stderr,"ERROR: reading header failed with error [%d]:\"%s\"\n",
                errno, strerror(errno));
        goto oops;
    }

    // Initialyzing SHA-1 context
    SHA_init(&ctx);

    // Saving header to file
    if ( save_header( lpcszParams, &Header) )
        goto oops;

    // Skipping padding
    if ( skip_padding(fd, Header.page_size, sizeof(Header)) )
        goto oops;

    // Extracting kernel image
    if ( extract_image(fd, Header.kernel_size, Header.page_size, lpcszKernel, &ctx) )
        goto oops;

    // Extracting ramdisk image
    if ( extract_image(fd, Header.ramdisk_size, Header.page_size, lpcszRamdisk, &ctx) )
        goto oops;

    // Extracting second image
    if ( extract_image(fd, Header.second_size, Header.page_size, lpcszSecond, &ctx) )
        goto oops;

    // Calculating ID
    sha = SHA_final(&ctx);
    if ( ! memcmp((uint8_t*)Header.id, sha,
           SHA_DIGEST_SIZE > sizeof(Header.id) ? sizeof(Header.id) : SHA_DIGEST_SIZE) ){
        printf("INFO: Checksum is GOOD\n");
    }
    else {
        fprintf(stderr,"ERROR: Checksum is BAD\n");
    }

    close(fd);
    return 0;
oops:
    close(fd);
    if(pData != NULL)
        free(pData);
    return 1;
}
