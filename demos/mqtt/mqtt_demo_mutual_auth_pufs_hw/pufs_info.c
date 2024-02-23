/***********************************************************************************
 *
 *  Copyright (c) 2022-2024, PUFsecurity
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
 *@file        pufs_info.c
 *
 *@brief       The source file implments PUFsecurity get information functions
 *
 *@copyright   2022-2024 PUFsecurity
 *
 ***************************************************************************************/

#include <stdio.h>
#include <string.h>
#include<stdbool.h>
#include "pufs_info.h"

#include<stdlib.h>
#include<unistd.h>
#include<time.h>

/*****************************************************************************
 * Define
 ****************************************************************************/
//#define INFO_DEBUG //print information

/*****************************************************************************
 * Macro Define
 ****************************************************************************/




/*****************************************************************************
 * Variable Define
 ****************************************************************************/


/*****************************************************************************/
/**
 * @fn      Getcpu
 * @brief   Get Cpu usage
 *
 * @return  CPUUsage
 *
 ****************************************************************************/
long double Getcpu()
{
    char str[100];
    const char d[2] = " ";
    char *token;
    int i = 0;
    long int sum = 0, idle = 0;
    long double CPUUsage;

    FILE *fp = fopen("/proc/stat", "r");
    i = 0;
    fgets(str, 100, fp);
    fclose(fp);
    token = strtok(str, d);
    sum = 0;
    while (token != NULL)
    {
        token = strtok(NULL, d);
        if (token != NULL)
        {
            sum += atoi(token);
            if (i == 3)
            {
                idle = atoi(token);
            }
            i++;
        }
    }

    CPUUsage = 100 - idle * 100.0 / sum;
#ifdef INFO_DEBUG
    printf("idle:%d,sum:%d\n", idle, sum);
    printf("CPUUsage : %lf %%.\n", CPUUsage);
#endif

    return CPUUsage;

}

/*****************************************************************************/
/**
 * @fn    parseLine
 * @brief parse line string to get value
 *
 * @return  value
 *
 ****************************************************************************/
int parseLine(char *line)
{
    // This assumes that a digit will be found and the line ends in " Kb".
    int i = strlen(line);
    const char *p = line;
    while (*p < '0' || *p > '9') p++;
    line[i - 3] = '\0';
    i = atoi(p);
    return i;
}

/*****************************************************************************/
/**
 * @fn    GetProcessMemory
 * @brief Get Memory usage
 *
 * @return  MemUsage
 *
 ****************************************************************************/
long double GetProcessMemory()
{
    FILE *file = fopen("/proc/meminfo", "r");
    char line[128];
    long int MemTotal = 1, MemFree = 0, Buffers = 0, Cached = 0;
    long double MemUsage = 0;
    int i = 0;
    while (i++ < 6)
    {
        fgets(line, 128, file);
        if (strncmp(line, "MemTotal:", 9) == 0)
        {
            MemTotal = parseLine(line);
        }
        else if (strncmp(line, "MemFree:", 8) == 0)
        {
            MemFree = parseLine(line);
        }
        else if (strncmp(line, "Buffers:", 8) == 0)
        {
            Buffers = parseLine(line);
        }
        else if (strncmp(line, "Cached:", 7) == 0)
        {
            Cached  = parseLine(line);
        }
    }

    MemUsage = 100 - (MemFree + Buffers + Cached) * 100.0 / MemTotal;
#ifdef INFO_DEBUG
    printf("MemTotal:%d kB, MemFree:%d kB, Buffers:%d kB, Cached:%d kB\n", MemTotal, MemFree, Buffers, Cached);
    printf("MemUsage : %lf %%.\n", MemUsage);
#endif
    fclose(file);
    return MemUsage;

}
/*****************************************************************************/
/**
 * @fn    Getcurrenttime
 * @brief Get time
 *
 * @return
 *
 ****************************************************************************/

void Getcurrenttime(char *t)
{
    time_t time_seconds = (time(0) + 28800);  //+8*60*60(+8hr)
    struct tm *now = localtime(&time_seconds);
    sprintf(t, "%04d%02d%02d %02d:%02d:%02d", now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min,
            now->tm_sec);
}
/*****************************************************************************/
/**
 * @fn    Gethealthreport_json
 * @brief Get info with json format and stored in content
 *
 * @return
 *
 ****************************************************************************/

void Gethealthreport_json(char *content)
{
    char command[100];
    strcpy(command, "sar -r 1 1 -o tmp1 &>/dev/null;sadf tmp1 -j --iface=eth0 -- -u -r -n DEV > data.txt;");
    system(command);
    FILE *file = fopen("data.txt", "r");
    char line[256];
    int a = 0;

    fgets(line, 256, file);
    strcpy(content, line);
    while ((fgets(line, 256, file) != NULL) && (a < 32))
    {
        strcat(content, line);
        a++;
    }
    //printf("a=%d file content:\n%s",a,content);
    fclose(file);

}
/*****************************************************************************/
/**
 * @fn    Gethealthreport_flatten
 * @brief Get info flatten with .csv and stored in content
 *
 * @return
 *
 ****************************************************************************/
void Gethealthreport_flatten(char *content)
{
    system("./read_info.sh;");
    FILE *fp = fopen("data.csv", "r");
    char row1[2048];
    char row2[2048];
    char *token;
    char health_info[2][30][30];
    int num = 0;

    FILE *fp2 = fopen("data.txt", "r");
    char reboot[15];
    char tmp[70];
    int i = 0;


    //read item_name
    fgets(row1, 2048, fp);
    //printf("Row: %s",row1);

    token = strtok(row1, ";[]%%#/ ");
    while (token != NULL)
    {
        if ((token[0] != '.') &&
            (token[0] != ' ') &&
            ((token[0] != 's') || ((token[1] >= 'a') && (token[1] <= 'z'))))
        {
            //printf("Token: %s\n", token);
            strcpy(health_info[0][num++], token);
        }

        token = strtok(NULL, ";[]%%#/ ");
    }

    //read data
    fgets(row2, 2048, fp);
    //printf("Row: %s",row2);

    token = strtok(row2, ";[]");
    num = 0;
    while (token != NULL)
    {
        if ((token[0] != '.') && (token[0] != ' '))
        {
            //printf("Token: %s\n", token);
            if ((strncmp(health_info[0][num], "CPU", 3) == 0) && (strncmp(token, "-1", 2) == 0))
            {
                strcpy(health_info[1][num++], "all");
            }
            else
            {
                strcpy(health_info[1][num++], token);
            }
        }

        token = strtok(NULL, ";[]");
    }

    fgets(reboot, 15, fp2);

    strcpy(content, "{");
    sprintf(tmp, "\"%s\":\"%s\"", health_info[0][0], health_info[1][0]);
    strcat(content, tmp);
    for (i = 1 ; i < num ; i++)
    {
        sprintf(tmp, ",\"%s\":\"%s\"", health_info[0][i], health_info[1][i]);
        strcat(content, tmp);
    }
    //reboot time
    sprintf(tmp, ",\"reboot\":\"%s\"", reboot);
    strcat(content, tmp);
    strcat(content, "}");

    system("rm tmp1;");
    fclose(fp);
    fclose(fp2);

}

/*****************************************************************************/
/**
 * @fn    GenerateExample_Payload
 * @brief Get info flatten with .csv and stored in content
 *
 * @return
 *
 ****************************************************************************/
void GenerateExample_Payload(char *base_msg, uint32_t len, char *content, uint32_t idx)
{
    char tmp[70];

    memcpy(content, base_msg, len);


    sprintf(tmp, " packet index: %d !!", idx);
    memcpy(content + len, tmp, strlen(tmp) + 1);
    //printf("content:%s size:%d\n", content, strlen(content));

}
