#include <QCryptographicHash>
#include <QVector>

#include "mythread.h"
#include "pcosynchro/pcothread.h"
#include "threadmanager.h"
#include <numeric>
#include <pcosynchro/pcologger.h>

extern QString resultat;

/*
 * std::pow pour les long long unsigned int
 */
long long unsigned int intPow(
        long long unsigned int number,
        long long unsigned int index) {
    long long unsigned int i;

    if (index == 0)
        return 1;

    long long unsigned int num = number;

    for (i = 1; i < index; i++)
        number *= num;

    return number;
}

ThreadManager::ThreadManager(QObject *parent) : QObject(parent) {}


void ThreadManager::incrementPercentComputed(double percentComputed) {
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
        unsigned int nbThreads) {

    logger().setVerbosity(0);


    //Init du resultat avant chaque nouvelle recherche de mot de passe
    resultat = "";

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
    long long unsigned int nbToCompute = intPow(charset.length(), nbChars);

    /*
     * Nombre de caractères différents pouvant composer le mot de passe
     */
    nbValidChars = charset.length();

    //Nombre de mot de passe à tester pour chaque thread, arrondi en à l'entier dessus pour couvrir jusqu'à la fin même s'il y a quelques overlaps.
    long long unsigned int nbToComputePerThread = ceil((double) nbToCompute / (double) nbThreads);
    //Index du premier mot de passe du dernier thread géré
    long long unsigned firstPasswordIndex = 0;


    logger() << std::endl
             << std::endl
             << "Starting bruteforce on " << hash.toStdString()
             << std::endl
             << "with nbToComputePerThread = " << nbToComputePerThread
             << " with pwd length of " << nbChars << " and "
             << nbThreads << " threads..." << std::endl
             << "Charset: " << charset.toStdString() << std::endl
             << std::endl
             << "Start:";

    std::vector<std::unique_ptr<PcoThread>> threadList;

    //S'il y a plus de thread que de valeur à calculer
    //(ce qui peut vite arriver sur des petits mots de passes)
    // on ne veut pas que des threads soient créés pour calculer un seul mot de passe doublon des autres.
    if (nbThreads >= nbToCompute) nbThreads = nbToCompute;

    /* Crée les threads, on ajoutant leur pointeur à la liste.
       Les threads sont immédiatement lancés par le constructeur. */
    for (unsigned int i = 0; i < nbThreads; i++) {

        /*
         * On initialise le premier mot de passe à tester courant en le remplissant
         * de nbChars fois du premier caractère de charset
         */
        //Set password to aaaa... and 0000... with the correct size (nbChars)
        currentPasswordString.fill(charset.at(0), nbChars);
        currentPasswordArray.fill(0, nbChars);

        //Génération du premier mot de passe pour le thread en cours, en fonction de firstPasswordIndex et de nbToComputePerThread
        long long decimalIndex = firstPasswordIndex;
        unsigned indexInPassword = 0;//index allant de droite à gauche pour prendre chaque digit l'un après l'autre
        while (decimalIndex > 0 && indexInPassword < nbChars) {
            currentPasswordArray[indexInPassword] = decimalIndex % nbValidChars;
            currentPasswordString[nbChars - indexInPassword - 1] = charset.at(decimalIndex % nbValidChars);

            decimalIndex /= nbValidChars;//Division par nbValidChars pour avoir le prochain digit à sa gauche au tour d'après
            ++indexInPassword;
        }

        logger() << std::endl
                 << "Setup thread " << i
                 << " with firstPasswordIndex = " << firstPasswordIndex
                 << " with first pwd=" << currentPasswordString.toStdString() << std::endl
                 //  << " with currentPasswordArray="
                 //  << currentPasswordArray.at(0) << " "
                 //  << currentPasswordArray.at(1) << " "
                 << std::endl;

        //Définir le prochain index de début pour le prochain thread
        firstPasswordIndex += nbToComputePerThread;
        //Ne pas créer de thread en plus quand on a dépassé le nombre total à créer
        if (firstPasswordIndex > nbToCompute) {
            nbThreads = i;
            break;
        }

        PcoThread *currentThread =
                new PcoThread(monHack, hash, salt, currentPasswordString,
                              currentPasswordArray, charset, nbChars,
                              nbToComputePerThread, nbToCompute, this);
        threadList.push_back(std::unique_ptr<PcoThread>(currentThread));
    }

    /* Attends la fin de chaque thread et libère la mémoire associée.
     * Durant l'attente, l'application est bloquée.
     */
    for (long unsigned int i = 0; i < nbThreads; i++) {
        threadList[i]->join();
    }

    /* Vide la liste de pointeurs de threads */
    threadList.clear();

    return resultat;
}
