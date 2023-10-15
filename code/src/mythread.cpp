#include "mythread.h"
#include "threadmanager.h"
#include <QCryptographicHash>
#include <QString>
#include <string>

QString resultat = "";//Mot de passe trouvé au final, reste "" si pas trouvé

void monHack(QString hash, QString salt, QString currentPasswordString, QVector<unsigned int> currentPasswordArray, QString charset, unsigned int nbChars, long long unsigned int nbToCompute,long long unsigned int maxCompute, ThreadManager *threadManager) {
    QString currentHash;
    unsigned int nbValidChars;
    unsigned int i;
    long long unsigned int nbComputed;

    nbComputed = 0;

    QCryptographicHash md5(QCryptographicHash::Md5);

    nbValidChars = charset.length();

    /*
     * Tant qu'on a pas tout essayé...
     */
    while (nbComputed <= nbToCompute) {
        /* On vide les données déjà ajoutées au générateur */
        md5.reset();
        /* On préfixe le mot de passe avec le sel */
        md5.addData(salt.toLatin1());
        md5.addData(currentPasswordString.toLatin1());
        /* On calcul le hash */
        currentHash = md5.result().toHex();

        /*
         * Si on a trouvé, on retourne le mot de passe courant (sans le sel) et on arrête la recherche
         */
        if (currentHash == hash){
            resultat = currentPasswordString;
            nbComputed = maxCompute;
        }

        /*
         * Tous les 1000 hash calculés, on notifie l'avancement des threads
         */
        if ((nbComputed % 1000) == 0) {
            threadManager->incrementPercentComputed((double)1000/maxCompute);
        }
        /*
         * On récupère le mot de pass à tester suivant.
         *
         * L'opération se résume à incrémenter currentPasswordArray comme si
         * chaque élément de ce vecteur représentait un digit d'un nombre en
         * base nbValidChars.
         *
         * Le digit de poids faible étant en position 0
         */
        i = 0;

        while (i < (unsigned int) currentPasswordArray.size()) {
            currentPasswordArray[i]++;

            if (currentPasswordArray[i] >= nbValidChars) {
                currentPasswordArray[i] = 0;
                i++;
            } else
                break;
        }

        /*
         * On traduit les index présents dans currentPasswordArray en
         * caractères
         */
        for (i = 0; i < nbChars; i++)
            currentPasswordString[i] = charset.at(currentPasswordArray.at(i));

        nbComputed++;
    }
}
