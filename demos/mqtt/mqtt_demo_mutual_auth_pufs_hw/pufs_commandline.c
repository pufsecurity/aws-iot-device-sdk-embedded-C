/***********************************************************************************
 *
 *  Copyright (c) 2023-2024, PUFsecurity
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *  3. Neither the name of PUFsecurity nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 *  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **************************************************************************************/

/*!*************************************************************************************
*
*@file        pufs_commandline.c
*
*@brief       This source file implements PUFsecurity command line functions
*
*@copyright   2023-2024 PUFsecurity
*
***************************************************************************************/

/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "demo_config.h"


const char *pufs_client_cert_path = NULL;
const char *pufs_client_identifier = NULL;
const char *pufs_client_topic = NULL;
uint32_t pufs_client_topic_len = 0;


void cmd_usage(const char *options, unsigned options_length)
{
    assert(NULL != options);

    /* For debugging printf( "options = %s %d\n", options, options_length ); */

    printf("Usage:\n");
    while (0 < options_length)
    {
        /* printf( "parsing option %c\n", *options ); */
        switch (*options)
        {

            case 'c':
                printf(
                       "-c --client_identifier\n\tProvide the client identifer registered in AWS IoT Core. For "
                       "example:\n"
                       "c-iot-test\n");
                break;

            case 'f':
                printf(
                       "-f --client_cert_filename\n\tThe filename of client certificate, including path from "
                       "cwd,\n");
                break;

            case 'h': /* Don't print anything for the help option since we're printing
                      usage */
                break;

            case ':': /* We'll skip the ':' character since it's not an option. */
                break;

            case '\0':
                break;

            default:
                printf("WARNING: Option %c not recognized by usage()\n", *options);
        }
        options++;
        options_length--;
    }
    printf("\n");
}


int cmd_parse(int argc, char **argv, char *valid_options,
              unsigned options_length)
{
    int c;
    int help_flag = 0;
    pufs_client_identifier = NULL;
    pufs_client_cert_path = NULL;

    while (1)
    {
        static struct option long_options[] =
        {
            {"help", no_argument, 0, 'h'},
            {"client_identifier", required_argument, 0, 'c'},
            {"client_cert_filename", optional_argument, 0, 'f'},
            {0, 0, 0, 0}
        };

        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, valid_options, long_options, &option_index);

        /* Detect the end of the options. */
        if (-1 == c)
        {
            break;
        }

        switch (c)
        {
            case 'c':
                pufs_client_identifier = optarg;
                break;
            case 'f':
                pufs_client_cert_path = optarg;
                break;
            case 'h':
            default:
                help_flag = 1;
                break;
        }
    }

    /* Print any unrecognized command line arguments. */
    if (optind < argc)
    {
        printf(
            "The application could not recognize the following non-option "
            "arguments: ");
        while (optind < argc)
        {
            printf("%s ", argv[optind++]);
        }
        putchar('\n');
    }
    putchar('\n');

    if (1 == help_flag) /* Print the usage statement */
    {
        cmd_usage(valid_options, options_length);
        return (-1); /* Don't run the application if -h --help was on the commandline */
    }

    return (0);
}




/*!*************************************************************************************
 *
 *@file        pufs_commandline.c
 *
 *@brief       commandline related function
 *
 *@copyright   2023 PUFsecurity
 *
 ***************************************************************************************/

int pufs_read_command_line(int argc, char *argv[])
{
    char options[] = "h:c:f:";
    int missingparameter = 0;
    int retval = 0;

    /* Parse the argv array for ONLY the options specified in the options string
     */
    retval = cmd_parse(argc, argv, options, sizeof(options));
    if (-1 == retval)
    {
        /* cmd_parse has returned an error, and has already logged the error
         to the console. Therefore just silently exit here. */

        return -1;
    }

    /* Check to see that the required parameters were all present on the command
     * line */
    if (NULL == pufs_client_identifier)
    {
        missingparameter = 1;

        pufs_client_identifier = CLIENT_IDENTIFIER;
        printf("-c --client_identifier is null. Use default %s\n");

    }

    if (NULL == pufs_client_cert_path)
    {
        missingparameter = 1;
        pufs_client_cert_path = CLIENT_CERT_PATH;
        printf("-f --client_cert_filename is null. Use default :%s\n");
    }

#if 0
    if (1 == missingparameter)
    {
        /* Error has already been logged, above.  Silently exit here */
        printf("\n");
        return -1;
    }
#endif

    return 0;

}
