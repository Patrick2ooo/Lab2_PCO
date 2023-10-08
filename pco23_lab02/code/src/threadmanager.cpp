#include <QCryptographicHash>
#include <QVector>

#include "threadmanager.h"
#include "pcosynchro/pcothread.h"
#include "mythread.h"
#include <future>

/*
 * std::pow pour les long long unsigned int
 */
long long unsigned int intPow (
        long long unsigned int number,
        long long unsigned int index)
{
    long long unsigned int i;

    if (index == 0)
        return 1;

    long long unsigned int num = number;

    for (i = 1; i < index; i++)
        number *= num;

    return number;
}

ThreadManager::ThreadManager(QObject *parent) :
    QObject(parent)
{}


void ThreadManager::incrementPercentComputed(double percentComputed)
{
    emit sig_incrementPercentComputed(percentComputed);
}

/*
 * Les paramètres sont les suivants:
 *
 * - charset:   QString contenant tous les caractères possibles du mot de passe
 * - salt:      le sel à concaténer au début du mot de passe avant de le hasher
 * - hash:      le hash dont on doit retrouver la préimage
 * - nbChars:   le nombre de caractères du mot de passe à bruteforcer
 * - nbThreads: le nombre de threads à lancer
 *
 * Cette fonction doit retourner le mot de passe correspondant au hash, ou une
 * chaine vide si non trouvé.
 */
QString ThreadManager::startHacking(
        QString charset,
        QString salt,
        QString hash,
        unsigned int nbChars,
        unsigned int nbThreads
)
{
    unsigned int i;

    long long unsigned int nbToCompute;
    long long unsigned int nbComputed;

    /*
     * Nombre de caractères différents pouvant composer le mot de passe
     */
    unsigned int nbValidChars;

    /*
     * Mot de passe à tester courant
     */
    QString currentPasswordString;

    /*
     * Tableau contenant les index dans la chaine charset des caractères de
     * currentPasswordString
     */
    QVector<unsigned int> currentPasswordArray;

    /*
     * Hash du mot de passe à tester courant
     */
    QString currentHash;

    /*
     * Object QCryptographicHash servant à générer des md5
     */
    QCryptographicHash md5(QCryptographicHash::Md5);

    /*
     * Calcul du nombre de hash à générer
     */
    nbToCompute        = intPow(charset.length(),nbChars);
    nbComputed         = 0;

    /*
     * Nombre de caractères différents pouvant composer le mot de passe
     */
    nbValidChars       = charset.length();

    /*
     * On initialise le premier mot de passe à tester courant en le remplissant
     * de nbChars fois du premier caractère de charset
     */
    int pos = 0;
    std::vector<std::unique_ptr<PcoThread>> threadList;
    QString resultat;
    std::vector<QString> results;
    //std::vector<std::future<QString>> futures;

    /* Crée les threads, on ajoutant leur pointeur à la liste.
       Les threads sont immédiatement lancés par le constructeur. */
    for(int i = 0; i < nbThreads; i++){

        currentPasswordString.fill(charset.at(pos),nbChars);
        currentPasswordArray.fill(0,nbChars);

        pos += nbValidChars/nbThreads;
        nbToCompute = nbToCompute/nbThreads;

        PcoThread *currentThread = new PcoThread([hash, salt, currentPasswordString, currentPasswordArray, charset, nbChars, nbToCompute, &resultat](){monHack(hash, salt, currentPasswordString, currentPasswordArray, charset, nbChars, nbToCompute, resultat);});
        threadList.push_back(std::unique_ptr<PcoThread>(currentThread));

        results.push_back(std::ref(resultat));

    }

    /* Attends la fin de chaque thread et libère la mémoire associée.
     * Durant l'attente, l'application est bloquée.
     */
    for (long unsigned int i=0; i<nbThreads; i++)
    {
        threadList[i]->join();
    }


    /* Vide la liste de pointeurs de threads */
    threadList.clear();

    for(const QString &res : results){
        if(res != QString("")){
            return resultat;
        }
    }

    /*
     * Tant qu'on a pas tout essayé...
     */
    /*while (nbComputed < nbToCompute) {
        /* On vide les données déjà ajoutées au générateur
        md5.reset();
        /* On préfixe le mot de passe avec le sel
        md5.addData(salt.toLatin1());
        md5.addData(currentPasswordString.toLatin1());
        /* On calcul le hash
        currentHash = md5.result().toHex();

        /*
         * Si on a trouvé, on retourne le mot de passe courant (sans le sel)

        if (currentHash == hash)
            return currentPasswordString;

        /*
         * Tous les 1000 hash calculés, on notifie qui veut bien entendre
         * de l'état de notre avancement (pour la barre de progression)

        if ((nbComputed % 1000) == 0) {
            incrementPercentComputed((double)1000/nbToCompute);
        }

        /*
         * On récupère le mot de pass à tester suivant.
         *
         * L'opération se résume à incrémenter currentPasswordArray comme si
         * chaque élément de ce vecteur représentait un digit d'un nombre en
         * base nbValidChars.
         *
         * Le digit de poids faible étant en position 0

        i = 0;

        while (i < (unsigned int)currentPasswordArray.size()) {
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

        for (i=0;i<nbChars;i++)
            currentPasswordString[i]  = charset.at(currentPasswordArray.at(i));

        nbComputed++;
    }*/
    /*
     * Si on arrive ici, cela signifie que tous les mot de passe possibles ont
     * été testés, et qu'aucun n'est la préimage de ce hash.
     */
    //return QString("");
}
