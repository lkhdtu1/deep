# Script Oral Detaille En Francais - Presentation 10 Slides

Ce script est une version plus precise du script oral. Il reprend les notes integrees dans la presentation et developpe surtout les slides 5 a 10, parce que ce sont les slides les plus techniques: explicabilite, stabilite, attaques, PGD, transferabilite, Security-OR et limites.

## Intention Generale A Garder Pendant Toute La Soutenance

Le projet ne doit pas etre presente comme un simple exercice de classification. Il faut le presenter comme une chaine complete de securite pour un IDS: on entraine plusieurs detecteurs, on choisit le meilleur compromis, on explique les decisions, on verifie si les explications sont stables, on teste si ces explications peuvent aider un attaquant, puis on evalue des defenses.

La phrase centrale a retenir est la suivante: le modele final Adv+ExtraTrees Ensemble IDS n'est pas declare invulnerable, mais il donne le meilleur equilibre teste entre performance propre, detection des familles rares, explicabilite, stabilite des explications et robustesse empirique contre les attaques evaluees.

## Slide 1 - Explainable IDS Under Adversarial Pressure

Bonjour. Nous sommes TAMIS Mohammed et GRYACH Ikram. Notre projet porte sur la detection d'intrusions explicable sous pression adversariale. Nous utilisons le dataset NSL-KDD, qui est le dataset demande dans le sujet, et nous construisons une pipeline complete allant du pretraitement jusqu'a l'analyse de securite.

Le modele final retenu est Adv+ExtraTrees Ensemble IDS. Il obtient un F1 binaire de 0.9063 et un PR-AUC de 0.9626. Mais l'idee principale n'est pas seulement d'avoir un score eleve. Dans un IDS, il faut aussi comprendre pourquoi une alerte est produite, verifier si cette explication est stable, et tester si un attaquant peut utiliser cette meme explication pour contourner le modele.

Le resultat de defense le plus fort concerne transfer-PGD. Les exemples adversariaux generes contre le modele Torch se transferent tres mal vers l'ensemble final. L'evasion devient 0.50% a eps 0.03, puis 0.00% a eps 0.06, 0.10 et 0.15. Je precise des maintenant que ce n'est pas une preuve de robustesse universelle. C'est une robustesse empirique dans les conditions d'attaque testees.

## Slide 2 - From Dataset To Defensible IDS Decision

Cette slide resume la logique globale du projet. Nous avons 125,973 exemples dans KDDTrain+ et 22,544 exemples dans KDDTest+. Apres pretraitement, nous obtenons 478 features. Le pretraitement comprend l'encodage one-hot des variables categorielles comme protocol, service et flag, la normalisation ou transformation des variables numeriques, et l'ajout de features derivees liees au trafic.

L'objectif IDS est d'abord binaire: distinguer le trafic normal du trafic attaque. Mais nous gardons aussi l'analyse par famille: DoS, Probe, R2L et U2R. C'est important parce qu'un modele peut avoir un bon score global et quand meme mal detecter les attaques rares.

La pipeline repond aux exigences du sujet. Nous entrainons des baselines et plusieurs variations, puis nous expliquons les decisions avec TreeSHAP, Integrated Gradients et SmoothIG. Ensuite, nous mesurons la stabilite des explications et nous testons des attaques: attaques guidees par SHAP, attaques guidees par Integrated Gradients, PGD complet, mutable-feature PGD et transfer-PGD. Enfin, nous evaluons les defenses: entrainement adversarial, ExtraTrees robuste augmente par SHAP et ensemble final.

## Slide 3 - Best Default Model: Adv+ExtraTrees Ensemble

Cette slide explique le choix du modele final. Adv+ExtraTrees obtient un F1 binaire de 0.9063, un PR-AUC de 0.9626 et une balanced accuracy de 0.9064. Ces trois metriques sont importantes. Le F1 mesure l'equilibre precision-rappel, le PR-AUC mesure la qualite du classement des attaques sur plusieurs seuils, et la balanced accuracy evite que la classe majoritaire domine l'evaluation.

Le modele final est aussi interessant parce qu'il ameliore les familles difficiles. DoS et Probe sont tres bien detectes, avec 0.9859 et 1.0000 de rappel. R2L et U2R restent plus difficiles, mais le modele final atteint 0.6786 pour R2L et 0.8060 pour U2R. C'est important parce que R2L et U2R sont souvent plus rares et plus proches du trafic normal.

La conclusion est que nous ne choisissons pas le modele seulement parce qu'il a un bon score global. Nous choisissons Adv+ExtraTrees parce qu'il offre le meilleur compromis entre performance propre, detection des familles rares, explicabilite et robustesse adversariale.

## Slide 4 - Explanations Show Meaningful Network Evidence

Cette slide explique ce que le modele final utilise pour prendre ses decisions. Les principales features sont liees a l'etat de connexion, aux taux de services identiques, aux compteurs cote hote, au login et aux erreurs. Ces features ont un sens en securite reseau: une attaque peut changer la frequence des services contactes, produire plus d'erreurs ou modifier les patterns de connexion.

Il faut etre tres clair sur les valeurs d'explicabilite. Une valeur SHAP et une valeur SmoothIG ne se comparent pas directement. SHAP donne des contributions dans l'echelle d'un modele arbre. SmoothIG donne des attributions basees sur des gradients integres d'un reseau neuronal. Donc si SHAP affiche une valeur moyenne autour de 0.02 et SmoothIG une valeur autour de 5, cela ne veut pas dire que SmoothIG est "250 fois plus important".

La bonne analyse est de regarder le classement des features dans chaque methode, la coherence securite de ces features, et la stabilite des explications. Ici, les features importantes sont defendables parce qu'elles correspondent a des comportements reseau logiques.

## Slide 5 - Different Explainers, Same Security Story

Cette slide repond a une question importante: pourquoi utiliser plusieurs methodes d'explicabilite? La raison est que les modeles ne sont pas de meme nature. TreeSHAP est adapte aux modeles a arbres, comme Random Forest ou ExtraTrees. Il attribue une contribution a chaque feature pour expliquer comment elle pousse la prediction vers normal ou attaque. Integrated Gradients et SmoothIG sont adaptes aux reseaux neuronaux, parce qu'ils utilisent les gradients du modele.

TreeSHAP doit etre compris comme une explication de contribution. Il nous dit quelles variables participent le plus a la decision d'un modele arbre. SmoothIG doit etre compris comme une attribution neuronale plus stable. Integrated Gradients calcule l'effet des features en suivant un chemin entre une entree de reference et l'entree reelle. SmoothIG repete ce calcul sur des versions legerement bruitees de l'entree et moyenne les resultats pour reduire le bruit des gradients.

La slide montre aussi les resultats de stabilite. La stabilite locale Jaccard mesure si les memes top features restent presentes quand on regarde des exemples proches ou legerement perturbes. Une valeur proche de 1 signifie que les explications restent similaires. Ici, RF SHAP obtient 0.880, Torch IG 0.881, SmoothIG 0.899 et l'ensemble final 0.845. Ces valeurs montrent que les explications sont assez stables pour etre discutees avec un analyste.

Mais la stabilite a deux faces. Du point de vue analyste, une explication stable inspire plus de confiance: le modele ne change pas completement de justification pour des exemples proches. Du point de vue attaquant, cette stabilite peut devenir dangereuse: si les memes features sont toujours importantes, un attaquant peut les cibler plus facilement. C'est pour cela que nous ne nous arretons pas a l'explicabilite. Nous testons aussi les attaques guidees par explication.

## Slide 6 - Explanations Help Analysts, But Also Guide Evasion

Cette slide presente l'idee la plus importante de la partie XAI securite: l'explicabilite est duale. Elle aide l'analyste a comprendre une alerte, mais elle peut aussi aider l'attaquant a choisir quelles features modifier.

Dans l'attaque SHAP-guided contre Random Forest, on identifie les features importantes selon SHAP, puis on modifie les features les plus influentes dans une direction qui rend l'attaque plus proche d'un comportement normal aux yeux du modele. Le meilleur resultat atteint 18.22% d'evasion. Cela signifie que, dans ce scenario, environ 18.22% des exemples d'attaque initialement detectes peuvent etre transformes pour ne plus etre detectes.

Dans l'attaque guidee par Integrated Gradients contre le MLP Torch, la logique est similaire, mais l'explication vient du modele neuronal. Les gradients indiquent quelles features influencent fortement le score. Le meilleur resultat atteint 15.97% d'evasion. Ce n'est pas une destruction totale du modele, mais c'est suffisant pour montrer que les explications peuvent devenir une information exploitable par un attaquant.

La troisieme figure est le contraste important. Contre l'ensemble final, l'attaque TreeSHAP-guided testee donne 0.00% d'evasion. Cela ne veut pas dire que le modele est invulnerable. Cela veut dire que, dans cette configuration d'attaque guidee par TreeSHAP, les modifications testees ne suffisent pas a faire passer les attaques comme normales. C'est un signe de durcissement du modele final.

La phrase a dire clairement est: l'explicabilite ne doit pas etre traitee seulement comme un outil de transparence, mais aussi comme une surface d'attaque potentielle.

## Slide 7 - Neural IDS Alone Remains Vulnerable

Cette slide explique pourquoi nous ne deployons pas le modele neuronal seul. PGD signifie Projected Gradient Descent. C'est une attaque white-box qui utilise les gradients du modele pour modifier l'entree dans une direction qui favorise l'evasion. Dans l'apprentissage normal, les gradients servent a ameliorer les poids du modele. Dans PGD, les gradients servent a modifier l'exemple d'entree pour tromper le modele.

Le full-feature PGD est un stress test tres fort. Il peut modifier toutes les features normalisees, y compris des features qui ne seraient pas librement modifiables dans un vrai trafic reseau. Par exemple, dans un vecteur tabulaire, modifier une variable one-hot de service ou de protocole peut etre possible mathematiquement, mais pas toujours realiste du point de vue reseau. C'est pourquoi nous le presentons comme un stress test, pas comme un scenario parfaitement realiste.

Le resultat est severe: le Torch Binary MLP original atteint 100% d'evasion sous full-feature PGD. Cela signifie qu'un modele neuronal differentiable, attaque directement avec ses gradients, est tres fragile. C'est une raison forte pour ne pas utiliser uniquement ce modele comme IDS final.

Ensuite, nous evaluons mutable-feature PGD. Cette version est plus realiste parce qu'elle gele les variables categorielles et binaires et ne modifie que des variables continues liees au comportement. Cela ne genere toujours pas de vrais paquets reseau, donc ce n'est pas parfait, mais c'est plus defendable qu'un PGD qui modifie tout.

L'entrainement adversarial ameliore surtout les budgets moyens et eleves. Pour mutable-feature PGD, la reduction est de 32.03 points a eps 0.10 et de 42.03 points a eps 0.15. Il existe aussi un cas negatif a eps 0.03 dans les resultats complets: cela montre que la defense ne s'ameliore pas uniformement partout. C'est justement pour cela que nous presentons plusieurs eps et que nous restons prudents dans l'analyse.

La conclusion de cette slide est que l'entrainement adversarial aide, mais ne suffit pas. Le modele neuronal seul reste trop vulnerable, donc la defense finale doit utiliser un ensemble heterogene.

## Slide 8 - The Final Ensemble Breaks Transferability

Cette slide est la plus importante pour defendre la partie adversariale. Il faut passer un peu plus de temps ici. Transfer-PGD signifie que l'attaque est d'abord construite contre un modele surrogate, ici le modele Torch, puis les exemples adversariaux obtenus sont testes sur un autre modele, ici l'ensemble Adv+ExtraTrees.

Pourquoi cette evaluation est importante? Parce que dans un vrai contexte, l'attaquant n'a pas toujours acces au modele final exact. Il peut entrainer ou attaquer un modele similaire, puis esperer que les exemples adversariaux se transferent vers le detecteur reel. C'est le principe de transferabilite.

Dans nos resultats, le modele Torch surrogate est vulnerable: l'evasion atteint 37.29%, 63.99%, 91.24% et 100.00% selon eps. Mais quand ces memes exemples sont testes sur l'ensemble final, l'evasion tombe a 0.50%, puis 0.00%, 0.00% et 0.00%. Cela signifie que les adversarial examples suivent bien la frontiere de decision du reseau neuronal, mais ne traversent pas efficacement la frontiere de decision de l'ensemble final.

La raison principale est l'heterogeneite. Le modele final combine une composante neuronale adversarialement fine-tuned et une composante ExtraTrees robuste, augmentee avec des perturbations guidees par SHAP. Les arbres n'ont pas la meme geometrie de decision qu'un reseau neuronal differentiable. Donc l'attaque optimisee par gradient contre le reseau ne se transfere pas bien vers l'ensemble.

Il faut etre precis dans la formulation: nous ne disons pas "le modele bloque toutes les attaques". Nous disons "dans le scenario transfer-PGD teste, le modele final casse fortement la transferabilite". C'est une affirmation forte, mais correcte et defendable.

## Slide 9 - Security-OR Is Optional, Not The Main Claim

Cette slide sert a eviter une confusion. Security-OR est un mode plus strict, mais ce n'est pas le modele principal. Son principe est simple: on declenche une alerte si l'une des composantes calibrees est suffisamment confiante que l'exemple est une attaque. C'est une logique de type "OR": si un detecteur voit un risque fort, on signale.

Ce mode est interessant en securite parce qu'il reduit les faux negatifs dans les attaques transfer-PGD testees. Dans nos resultats corriges, il obtient 0.00% d'evasion transfer-PGD. Mais il a un cout: son F1 propre est plus faible, 0.8796, alors que le modele Adv+ExtraTrees atteint 0.9063.

Cela signifie que Security-OR peut generer plus d'alertes ou perdre en equilibre global. Dans un SOC ou un environnement critique, ce compromis peut etre acceptable si rater une attaque coute tres cher. Mais pour le modele final par defaut du projet, Adv+ExtraTrees est meilleur car il equilibre mieux performance propre et robustesse.

Les limites doivent etre dites clairement. NSL-KDD est ancien. Les attaques en espace de features ne sont pas identiques a des attaques reseau reelles au niveau paquets. Les familles R2L et U2R restent difficiles. Et surtout, nos resultats sont empiriques: ils prouvent une robustesse sous les attaques testees, pas une garantie mathematique contre toutes les attaques possibles.

## Slide 10 - What This Project Demonstrates

La conclusion doit revenir aux livrables du sujet. Nous avons entraine un IDS, compare une baseline et plusieurs variations, explique les decisions, mesure la stabilite, analyse le risque de securite des explications, attaque les modeles, puis evalue des defenses.

Le modele final obtient 0.9063 de F1 binaire, 0.9626 de PR-AUC, 0.9064 de balanced accuracy et 0.845 de stabilite locale des explications. Il ameliore aussi la detection des familles difficiles, notamment U2R avec 0.806 de rappel. Enfin, il reduit fortement l'evasion transfer-PGD testee.

Le message final est que l'explicabilite est necessaire pour la confiance, mais qu'en cybersécurité elle doit aussi etre testee comme une surface d'attaque. Un bon IDS explicable doit donc etre performant, comprehensible, stable et teste sous pression adversariale.

Si on me demande de resumer le projet en une phrase: Adv+ExtraTrees n'est pas une defense universelle, mais c'est le meilleur compromis teste entre detection, explicabilite, stabilite et robustesse empirique sur NSL-KDD.
