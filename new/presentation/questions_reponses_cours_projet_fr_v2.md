# Questions-Reponses V2 - Cours Et Projet IDS Explicable

Ce document prepare les questions probables qui relient le projet aux cours: introduction au deep learning, MLP, fonctions d'activation, loss, gradient descent, CNN, RNN/LSTM/GRU, autoencoders, GANs, transformers, attention, explainability et adversarial robustness.

Les reponses gardent volontairement plusieurs termes en anglais: `features`, `preprocessing`, `recall`, `threshold`, `TreeSHAP`, `SmoothIG`, `PGD`, `evasion`, `surrogate`, `transfer`, `ensemble`, `baseline`. Ce sont les termes les plus naturels pour defendre le projet.

## A. Questions Generales Sur Le Projet

### 1. Quel est l'objectif principal du projet?

L'objectif est de construire un IDS explicable sur NSL-KDD. Le projet ne consiste pas seulement a entrainer un modele qui predit `normal` ou `attack`. Il faut aussi expliquer les decisions, verifier si les explications sont stables, analyser si ces explications peuvent guider des attaques, puis evaluer des defenses adversariales.

### 2. Quelle est la difference entre un IDS classique et notre IDS explicable?

Un IDS classique peut simplement produire une alerte. Un IDS explicable doit aussi donner des raisons: quelles `features` ont influence la decision, est-ce que ces raisons sont coherentes avec la securite reseau, et est-ce que ces raisons restent stables. Dans notre projet, cette explication est faite avec `TreeSHAP`, `Integrated Gradients` et `SmoothIG`.

### 3. Pourquoi NSL-KDD?

NSL-KDD est le dataset impose par le sujet et c'est un benchmark connu pour IDS. Il donne un split train/test standardise, ce qui facilite la reproductibilite. Sa limite est qu'il est ancien et ne represente pas parfaitement le trafic moderne. C'est pour cela que nous presentons les resultats comme valables sur ce benchmark, pas comme une garantie generale.

### 4. Pourquoi R2L et U2R sont difficiles?

R2L et U2R sont rares et plus subtils. DoS et Probe creent souvent des patterns plus visibles, comme beaucoup de connexions, des scans ou des erreurs. R2L et U2R peuvent ressembler davantage a du trafic normal. C'est pour cela que nous regardons le `recall` par famille, pas seulement le score global.

### 5. Pourquoi ne pas utiliser seulement accuracy?

L'accuracy peut cacher les erreurs sur les classes rares. Par exemple, un modele peut bien detecter DoS et Probe mais rater R2L. En IDS, un faux negatif peut etre grave. Nous utilisons donc `F1`, `PR-AUC`, `balanced accuracy` et `family recall`.

### 6. Pourquoi le modele final est Adv+ExtraTrees?

Adv+ExtraTrees donne le meilleur compromis. Il obtient `F1 = 0.9063`, `PR-AUC = 0.9626` et `balanced accuracy = 0.9064`. Il combine un modele neuronal adversarialement fine-tuned avec un ExtraTrees robuste augmente avec des perturbations guidees par SHAP. Il donne aussi le meilleur resultat de defense contre `transfer-PGD`.

### 7. Pourquoi Security-OR n'est pas le modele principal?

`Security-OR` est un mode strict. Il declenche plus facilement une alerte si une composante du systeme voit un risque fort. Il est tres interessant pour reduire l'evasion transfer-PGD, mais son `F1` propre est plus faible: 0.8796 contre 0.9063 pour Adv+ExtraTrees. Donc il est optionnel pour un contexte haute securite, mais pas le meilleur compromis general.

### 8. Que veut dire `pp` dans les reductions?

`pp` signifie `percentage points`, ou points de pourcentage. Si l'evasion passe de 71.21% a 39.18%, la reduction absolue est 71.21 - 39.18 = 32.03 pp. Ce n'est pas une reduction relative; c'est une difference directe entre deux pourcentages.

## B. Questions Sur Le Preprocessing

### 9. Qu'avez-vous fait dans le preprocessing?

Nous avons charge les splits NSL-KDD, transforme les labels en decision binaire et en familles d'attaque, encode les variables categorielles avec `one-hot encoding`, transforme et mis a l'echelle les variables numeriques, ajoute des `features` derivees comme des ratios et des gaps d'erreurs, puis aligne les colonnes train/test. Le resultat est une matrice de 478 features.

### 10. Pourquoi utiliser one-hot encoding?

Parce que les variables comme `protocol_type`, `service` et `flag` sont categorielles. Si on les codait avec 1, 2, 3, le modele pourrait croire qu'il existe un ordre artificiel. Le one-hot encoding cree des colonnes binaires et evite cette erreur.

### 11. Pourquoi faire du feature engineering?

Les features derivees capturent des relations importantes. Par exemple, un ratio de bytes ou un gap d'erreurs peut etre plus informatif qu'une variable brute seule. En securite reseau, les relations entre compteurs, erreurs, services et connexions sont souvent tres importantes.

### 12. Pourquoi le scaling est important?

Le scaling est surtout important pour les modeles neuronaux et les methodes basees sur des distances ou gradients. Si une feature a des valeurs beaucoup plus grandes que les autres, elle peut dominer l'apprentissage. Le scaling rend les features plus comparables.

## C. Questions Sur Les Modeles

### 13. Qu'est-ce que Logistic Regression dans votre projet?

C'est la `baseline` lineaire. Elle apprend une combinaison ponderee des features pour separer normal et attack. Elle est simple, rapide et utile pour verifier que les modeles plus complexes apportent vraiment quelque chose.

### 14. Qu'est-ce que Random Forest?

Random Forest est un ensemble de decision trees. Chaque arbre apprend des regles de decision, et la foret combine les votes ou scores de plusieurs arbres. C'est fort sur donnees tabulaires et compatible avec `TreeSHAP`.

### 15. Qu'est-ce que ExtraTrees?

ExtraTrees ressemble a Random Forest, mais ajoute plus de hasard dans les splits des arbres. Cette randomisation augmente la diversite des arbres. Dans notre projet, ExtraTrees est important parce qu'il sert de composante robuste dans le modele final.

### 16. Qu'est-ce que XGBoost?

XGBoost est un modele de gradient boosting. Il construit les arbres progressivement, chaque nouvel arbre corrigeant les erreurs des precedents. C'est une baseline tabulaire forte.

### 17. Qu'est-ce que le Torch MLP?

Le Torch MLP est un reseau neuronal fully connected. Il prend les 478 features en entree, passe par des couches cachees avec activations non lineaires, puis produit une prediction. Il est important parce qu'il est differentiable, donc compatible avec `Integrated Gradients` et `PGD`.

### 18. Pourquoi utiliser un MLP au lieu d'un modele deep plus complique?

NSL-KDD est tabulaire. Un MLP est adapte a un vecteur de features. Un modele plus profond ou plus complexe pourrait augmenter le cout et le risque d'overfitting sans benefice clair. Le sujet demande aussi des modeles raisonnables en temps de calcul.

### 19. Pourquoi ne pas utiliser KNN?

KNN compare un exemple test aux exemples train les plus proches. Avec 125,973 exemples et 478 features, cela peut etre couteux. En plus, dans un espace one-hot de grande dimension, la notion de distance peut devenir moins fiable. KNN n'apporte pas beaucoup pour l'explainability ni pour l'analyse adversariale.

### 20. Pourquoi ne pas utiliser SVM?

Un SVM lineaire serait proche d'une baseline lineaire comme Logistic Regression. Un SVM non lineaire peut devenir couteux sur un dataset de cette taille et avec beaucoup de features. Il aurait ete possible de le tester, mais il etait moins prioritaire que les modeles plus utiles pour XAI et PGD.

### 21. Pourquoi ne pas utiliser Naive Bayes?

Naive Bayes suppose que les features sont conditionnellement independantes. Dans NSL-KDD, beaucoup de features sont correlees: counts, rates, flags, services et erreurs. Cette hypothese est donc trop forte pour etre le modele principal.

### 22. Pourquoi ne pas utiliser CNN?

Les CNN sont adaptes aux images et aux grilles, car ils exploitent la localite spatiale. NSL-KDD est tabulaire. Les colonnes voisines n'ont pas forcement de relation spatiale. Transformer les features en pseudo-image serait artificiel.

### 23. Pourquoi ne pas utiliser RNN ou LSTM?

Les RNN/LSTM sont adaptes aux sequences avec dependances temporelles. NSL-KDD contient des connexions individuelles, pas des sequences completes de paquets ou de sessions. Un RNN serait plus adapte si nous avions des logs ou des flows ordonnes dans le temps.

### 24. Pourquoi ne pas utiliser Transformer?

Les transformers sont puissants pour les sequences de tokens grace a l'attention. Ici, l'entree est un vecteur tabulaire fixe. Un transformer ajouterait de la complexite sans avantage clair. Il serait plus pertinent pour des logs, du texte ou des sequences de paquets.

## D. Questions Reliees Au Cours Deep Learning

### 25. Comment ce projet se relie au deep learning vu en cours?

Le cours explique que le deep learning apprend des representations automatiquement. Dans notre projet, le MLP apprend des combinaisons non lineaires de features. Mais comme les donnees sont tabulaires, nous combinons aussi des modeles arbres, qui sont souvent tres efficaces pour ce type de donnees.

### 26. Quel est le role des activation functions?

Les activation functions introduisent la non-linearite. Sans elles, plusieurs couches lineaires se reduiraient a une seule transformation lineaire. Dans notre MLP, elles permettent d'apprendre des frontieres complexes entre normal et attack.

### 27. Pourquoi ReLU est utile?

ReLU est efficace et limite mieux le probleme de vanishing gradient que sigmoid ou tanh dans les couches cachees. C'est une activation standard pour entrainer des reseaux rapidement et de maniere stable.

### 28. Quelle loss est adaptee a la classification binaire?

Pour une decision normal/attack, la loss adaptee est `binary cross-entropy`. Elle penalise les probabilites incorrectes et fonctionne naturellement avec une sortie de type sigmoid ou score binaire.

### 29. Pourquoi cross-entropy et pas MSE?

MSE est plus adaptee a la regression ou a la reconstruction, par exemple dans les autoencoders. Pour la classification, cross-entropy optimise directement les probabilites de classes.

### 30. Comment la backpropagation apparait dans le projet?

Elle sert a entrainer les modeles Torch. Le modele fait une prediction, calcule une loss, puis backpropagation calcule les gradients pour mettre a jour les poids. PGD utilise aussi les gradients, mais par rapport aux entrees, pour creer des exemples adversariaux.

### 31. Quelle est la difference entre gradient descent et PGD?

Gradient descent modifie les poids pour reduire la loss. PGD adversarial modifie l'entree pour augmenter l'erreur ou reduire le score attack. Dans un cas, les gradients servent a apprendre; dans l'autre, ils servent a attaquer.

### 32. Pourquoi les mini-batches sont utiles?

Les mini-batches donnent un compromis entre stabilite et efficacite. Ils permettent d'utiliser le GPU et d'obtenir un apprentissage plus stable qu'un exemple a la fois, tout en etant moins lourd que tout le dataset a chaque update.

## E. Questions Sur Explainability

### 33. Qu'est-ce que TreeSHAP?

TreeSHAP est une methode d'explication pour les modeles a arbres. Elle attribue a chaque feature une contribution dans la prediction. Dans notre projet, elle explique Random Forest, ExtraTrees et l'ensemble final.

### 34. Qu'est-ce que Integrated Gradients?

Integrated Gradients est une methode d'explication pour reseaux neuronaux. Elle part d'une baseline et va vers l'entree reelle en accumulant les gradients. Elle montre quelles features contribuent le plus au score du modele.

### 35. Qu'est-ce que SmoothIG?

SmoothIG est une version stabilisee d'Integrated Gradients. On ajoute de petits bruits a l'entree, on calcule plusieurs attributions, puis on moyenne. Cela reduit le bruit des gradients et rend l'explication plus stable.

### 36. Pourquoi SHAP et SmoothIG n'ont pas la meme echelle?

TreeSHAP mesure des contributions dans un modele arbre. SmoothIG mesure des magnitudes de gradients integres dans un reseau neuronal. Ce ne sont pas les memes unites. Il faut comparer les `ranks`, la coherence des features et la stability, pas les valeurs brutes.

### 37. Qu'est-ce que la stability des explications?

La stability mesure si les features importantes restent similaires quand les exemples sont proches ou quand les donnees sont reechantillonnees. Une explication stable est plus fiable pour un analyste, mais elle peut aussi donner a l'attaquant des cibles plus previsibles.

### 38. Pourquoi montrer seulement local Jaccard dans la presentation?

Parce que la presentation doit rester courte. `local Jaccard` est la metric la plus intuitive: elle mesure si les memes top features reviennent dans des exemples proches. Mais dans les resultats complets, nous avons aussi `local rank`, `bootstrap Jaccard` et `bootstrap rank`.

### 39. Exemple simple de local Jaccard?

Si l'explication A donne `{flag_SF, same_srv_rate, rerror_rate}` et l'explication B donne `{flag_SF, same_srv_rate, logged_in}`, l'intersection contient 2 features et l'union 4 features. Donc Jaccard = 2/4 = 0.5. Plus la valeur est proche de 1, plus les explications se ressemblent.

### 40. Pourquoi l'explicabilite peut etre dangereuse?

Parce qu'elle indique les features importantes. Un analyste utilise ces informations pour comprendre l'alerte, mais un attaquant peut les utiliser pour modifier les features les plus sensibles. C'est le probleme dual-use de l'explainability.

## F. Questions Sur Les Attaques Et Defenses

### 41. Qu'est-ce qu'une attaque SHAP-guided?

C'est une attaque qui utilise les features importantes selon SHAP pour choisir quoi modifier. Dans notre projet, elle atteint jusqu'a 18.22% d'evasion contre Random Forest.

### 42. Qu'est-ce qu'une attaque IG-guided?

C'est une attaque qui utilise les attributions Integrated Gradients du modele neuronal pour choisir les features a modifier. Elle atteint jusqu'a 15.97% d'evasion contre le Torch MLP.

### 43. Qu'est-ce que PGD?

PGD signifie Projected Gradient Descent. C'est une attaque iterative qui modifie l'entree dans la direction du gradient pour tromper le modele, tout en limitant la perturbation avec un budget `eps`.

### 44. Difference entre full-feature PGD et mutable-feature PGD?

Full-feature PGD peut modifier toutes les features normalisees, donc c'est tres fort mais pas toujours realiste. Mutable-feature PGD bloque les features categorielles et binaires, puis modifie seulement les features continues. C'est plus defendable pour des donnees tabulaires reseau.

### 45. Pourquoi le modele Torch seul est vulnerable?

Parce qu'il est differentiable. PGD peut utiliser ses gradients pour trouver rapidement une direction qui reduit le score attack. Dans nos resultats, full-feature PGD atteint 100% d'evasion contre le Torch Binary MLP original.

### 46. Qu'est-ce que adversarial fine-tuning?

C'est le fait de continuer l'entrainement avec des exemples adversariaux. Le modele apprend que certaines versions perturbees d'attaques doivent rester classees comme attack. Cela ameliore surtout mutable-feature PGD a eps moyens et eleves.

### 47. Que veut dire surrogate Torch?

`Surrogate Torch` signifie que le modele Torch est utilise comme modele de substitution pour construire l'attaque PGD. Les exemples adversariaux sont generes contre Torch, puis testes contre le modele final Adv+ExtraTrees. Si ces exemples ne trompent pas le modele final, cela veut dire que la transferability est faible.

### 48. Qu'est-ce que transfer-PGD?

Transfer-PGD est une attaque generee contre un surrogate, puis transferee vers un autre modele. Dans nos resultats, l'evasion est forte sur Torch, mais devient 0.50%, 0.00%, 0.00% et 0.00% sur l'ensemble final. C'est notre meilleur resultat de defense.

### 49. Pourquoi Adv+ExtraTrees casse la transferability?

Parce que l'attaque PGD suit la frontiere differentiable du reseau Torch. Or l'ensemble final contient une composante ExtraTrees robuste, non differentiable de la meme maniere, et entrainee avec des perturbations guidees par SHAP. Les adversarial examples optimises pour Torch ne correspondent donc pas bien a la frontiere de decision finale.

### 50. Qu'est-ce que Security-OR?

Security-OR est un mode strict optionnel. Il utilise les scores des composantes deja entrainees et les compare a leurs thresholds calibres. Si une composante indique un risque fort, le systeme peut declencher l'alerte. C'est utile pour un contexte haute securite, mais ce n'est pas le modele final par defaut car son F1 est plus faible.

### 51. Est-ce que 0.00% evasion veut dire modele invulnerable?

Non. Cela veut dire 0.00% dans les attaques et parametres testes. Ce n'est pas une robustesse certifiee. Un attaquant adaptatif, un autre dataset ou des attaques plus realistes au niveau paquet pourraient donner d'autres resultats.

### 52. Quelle est la principale limite du projet?

Les principales limites sont: NSL-KDD est ancien, les attaques feature-space ne sont pas toujours parfaitement realistes, R2L reste difficile, et la robustesse n'est pas certifiee mathematiquement.

## G. Questions Sur Autoencoders, GANs Et Transformers

### 53. Quel lien avec les autoencoders vus en cours?

Les autoencoders peuvent servir a l'anomaly detection. On les entraine sur du trafic normal, puis une forte reconstruction error peut indiquer une anomalie. Dans notre projet, nous avons choisi une approche supervisee car NSL-KDD fournit des labels.

### 54. Pourquoi ne pas utiliser un autoencoder comme modele final?

Un autoencoder est surtout utile quand les labels sont absents ou pour une detection non supervisee. Ici, nous avons des labels et nous devons evaluer precision, recall, F1, PR-AUC et families. Les modeles supervises sont plus directs pour le sujet.

### 55. Est-ce qu'un denoising autoencoder pourrait aider contre les attaques?

Potentiellement oui. Il pourrait servir de preprocesseur pour nettoyer des perturbations. Mais il faudrait verifier qu'un attaquant ne peut pas contourner ce denoising. Ce serait une extension future, pas le coeur du projet actuel.

### 56. Quel lien avec les GANs?

Les GANs utilisent une logique adversariale entre un generator et un discriminator. Ce n'est pas la meme chose que PGD, mais l'idee d'opposition est similaire. Un GAN pourrait generer des attaques synthetiques rares, mais il faudrait garantir leur realisme.

### 57. Quel lien avec les transformers?

Les transformers utilisent l'attention pour modeliser des sequences de tokens. Dans un IDS moderne base sur logs ou sequences de paquets, un transformer pourrait etre utile. Dans notre projet, les donnees sont tabulaires, donc ce n'est pas le choix le plus naturel.

### 58. Quelle difference entre attention et SHAP?

L'attention est un mecanisme interne au modele transformer. SHAP est une methode post-hoc qui explique une prediction apres entrainement. Les deux peuvent aider a interpreter, mais ils ne mesurent pas la meme chose.

## H. Reponses Tres Courtes A Memoriser

### 59. Si on demande le meilleur resultat du projet?

Le meilleur resultat est la defense `transfer-PGD`: les attaques qui trompent fortement le surrogate Torch ne se transferent presque pas vers Adv+ExtraTrees.

### 60. Si on demande pourquoi votre projet est defendable?

Parce qu'il suit tout le cycle demande: preprocessing reproductible, baseline, plusieurs variations, metrics propres, explainability, stability, attaques, defenses, resultats, et limites clairement annoncees.

### 61. Si on demande la phrase finale?

Adv+ExtraTrees n'est pas une defense universelle, mais c'est le meilleur compromis teste entre IDS performance, explainability, stability et robustness empirique sur NSL-KDD.
