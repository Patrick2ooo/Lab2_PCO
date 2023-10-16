#ifndef MYTHREAD_H
#define MYTHREAD_H

#include "threadmanager.h"
#include <QString>
#include <pcosynchro/pcothread.h>


/**
 * \brief Cette fonction calcul les hash de tout les mot de passe possible et les compare avec le hash que l'on recherche.
 *
 * \param hash du mot de passe à trouvé
 * \param salt est la partie du code que l'on connait déjà
 * \param currentPasswordString est le premier mot de passe à tester
 * \param currentPasswordArray tableau contenant les index dans la chaine charset des caractères de currentPasswordString
 * \param charset tout les caractère pouvant être utilisé dans notre mot de passe
 * \param nbChars nombre de caractère de notre mot de passe
 * \param nbToCompute nombre de mot de passe à tester
 * \param maxCompute maximum de mot de passe à tester lors de multithreading
 * \param threadManager permet l'appelle aux méthode de la classe ThreeadManager
 */
void monHack(QString hash, QString salt, QString currentPasswordString,
             QVector<unsigned int> currentPasswordArray, QString charset,
             unsigned int nbChars, long long unsigned int nbToCompute,
             long long unsigned int maxCompute, ThreadManager *threadManager);

#endif// MYTHREAD_H
