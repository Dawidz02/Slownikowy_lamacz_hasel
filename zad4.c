#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>

void bytes2md5(const char *data, int len, char *md5buf)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);
    for (i = 0; i < md_len; i++)
    {
        snprintf(&(md5buf[i * 2]), 16 * 2, "%02x", md_value[i]);
    }
}


#define MAX_DL_SLOWA 20
#define MAX_DL_SLOWA2 33
#define MAX_L_SLOW 15
#define L_HASEL_DO_ZLAMANIA 181
char tablicaHaszowDoZlamania[L_HASEL_DO_ZLAMANIA][33];
char nazwa_uzytkownika[L_HASEL_DO_ZLAMANIA][50];

void dopasowywanie(char haslo[], char hasz[])
{
    bytes2md5(haslo, strlen(haslo), hasz);
    for (int i = 0; i < L_HASEL_DO_ZLAMANIA; i++)
    {
        if (strcmp(tablicaHaszowDoZlamania[i], hasz) == 0)
        {
            printf("Password for %s is %s\n", nazwa_uzytkownika[i], haslo);
        }
    }
}


int liczbaLini(char nazwa_pliku[])
{
    FILE *plik;
    char linia[1000];
    int liczba_linii = 0;

    plik = fopen(nazwa_pliku, "r");

    if (plik == NULL) {
        printf("Nie można otworzyć pliku.\n");
        return 1;
    }

    while (fgets(linia, sizeof(linia), plik) != NULL) {
        liczba_linii++;
    }

    fclose(plik);
    return liczba_linii;
}


int main()
{
    FILE *plik, *plik2;
    int liczba_lini = liczbaLini("slownik4.txt")+1;
    char slowo[MAX_DL_SLOWA];
    int liczba_slow = 0;
    char linia[150];
    /* Dynamiczne zalokowanie pamieci */
    char **tablicaSlownik = (char**)malloc(liczba_lini * sizeof(char*));
    for(int i = 0; i < liczba_lini; i++)
    {
        tablicaSlownik[i] = (char*)malloc(MAX_DL_SLOWA * sizeof(char)); 
    }

    char **tablicaHaszow = (char**)malloc(liczba_lini * sizeof(char*)); 
    for(int i = 0; i < liczba_lini; i++)
    {
        tablicaHaszow[i] = (char*)malloc(MAX_DL_SLOWA2 * sizeof(char)); 
    }

    plik = fopen("slownik4.txt", "r");
    if (plik == NULL)
    {
        printf("Błąd podczas wczytywania pliku.\n");
        return 1;
    }
    plik2 = fopen("hasla4.txt", "r");
    if (plik2 == NULL)
    {
        printf("Błąd podczas wczytywania pliku.\n");
        return 1;
    }

    /* Wczytanie haseł do złamania do tablicy */
    int t = 0;
    while (fgets(linia, sizeof(linia), plik2))
    {
        char *slowo2 = strtok(linia, " \t");
        t = 0;
        while (t < 4)
        {
            if (t == 1)
            {
                strcpy(tablicaHaszowDoZlamania[liczba_slow], slowo2);
            }
            if (t == 2)
            {
                strcpy(nazwa_uzytkownika[liczba_slow], slowo2);
            }
            slowo2 = strtok(NULL, " \t");
            t++;
        }
        liczba_slow++;
    }
    liczba_slow = 0;

    /* Wczytanie haseł do tablicy */
    while (fscanf(plik, "%s", slowo) != EOF && liczba_slow <= liczba_lini)
    {
        strcpy(tablicaSlownik[liczba_slow], slowo);
        liczba_slow++;
    }
    

    /* Dopasowywanie hasel */
    for (int j = 0; j < liczba_slow; j++)
    {
        dopasowywanie(tablicaSlownik[j], tablicaHaszow[j]);
    }

    /* Dodanie cyfr na poczatku i koncu hasla i dopasowanie */
    int pom = liczba_slow;
    int pom2 = 0;

    while (pom2 < liczba_slow)
    {
        for (int k = 0; k < 3; k++)
        {
            if (k == 2)
            {
                for (int i = 0; tablicaSlownik[pom2][i] != '\0'; i++) 
                {
                    tablicaSlownik[pom2][i] = toupper(tablicaSlownik[pom2][i]);
                }
                dopasowywanie(tablicaSlownik[pom2], tablicaHaszow[pom]);

                for (int i = 1; i <= 99; i++)
                {
                    sprintf(tablicaSlownik[pom], "%d%s", i, tablicaSlownik[pom2]);
                    dopasowywanie(tablicaSlownik[pom], tablicaHaszow[pom]);

                    sprintf(tablicaSlownik[pom], "%s%d", tablicaSlownik[pom2], i);
                    dopasowywanie(tablicaSlownik[pom], tablicaHaszow[pom]);

                    for (int j = 1; j <= 99; j++)
                    {
                        sprintf(tablicaSlownik[pom], "%d%s%d", i, tablicaSlownik[pom2], j);
                        dopasowywanie(tablicaSlownik[pom], tablicaHaszow[pom]);
                    }
                }
            }

            if (k == 1)
            {
                tablicaSlownik[pom2][0] = toupper(tablicaSlownik[pom2][0]);
                dopasowywanie(tablicaSlownik[pom], tablicaHaszow[pom]);

                for (int i = 1; i <= 99; i++)
                {
                    sprintf(tablicaSlownik[pom], "%d%s", i, tablicaSlownik[pom2]);
                    dopasowywanie(tablicaSlownik[pom], tablicaHaszow[pom]);

                    sprintf(tablicaSlownik[pom], "%s%d", tablicaSlownik[pom2], i);
                    dopasowywanie(tablicaSlownik[pom], tablicaHaszow[pom]);

                    for (int j = 1; j <= 99; j++)
                    {
                        sprintf(tablicaSlownik[pom], "%d%s%d", i, tablicaSlownik[pom2], j);
                        dopasowywanie(tablicaSlownik[pom], tablicaHaszow[pom]);
                    }
                }
            }

            if (k == 0)
            {
                for (int i = 1; i <= 99; i++)
                {
                    sprintf(tablicaSlownik[pom], "%d%s", i, tablicaSlownik[pom2]);
                    dopasowywanie(tablicaSlownik[pom], tablicaHaszow[pom]);

                    sprintf(tablicaSlownik[pom], "%s%d", tablicaSlownik[pom2], i);
                    dopasowywanie(tablicaSlownik[pom], tablicaHaszow[pom]);

                    for (int j = 1; j <= 99; j++)
                    {
                        sprintf(tablicaSlownik[pom], "%d%s%d", i, tablicaSlownik[pom2], j);
                        dopasowywanie(tablicaSlownik[pom], tablicaHaszow[pom]);
                    }
                }
            }
        }
        pom2++;
    }

    for(int i = 0; i < liczba_lini; i++)
    {
        free(tablicaSlownik[i]);
        free(tablicaHaszow[i]);
    }
    free(tablicaSlownik);
    free(tablicaHaszow);
    
    fclose(plik);
    fclose(plik2);
    return 0;
}