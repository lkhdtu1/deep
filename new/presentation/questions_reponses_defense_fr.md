# Questions-Réponses En Français Pour La Soutenance

Ce fichier regroupe des questions probables pour la soutenance. Les réponses sont adaptées au projet et aux notions vues en cours: MLP, fonctions d'activation, loss, descente de gradient, CNN, RNN, autoencodeurs, GANs, transformers, attention et explicabilité.

## 1. Quel est l'objectif principal du projet?

L'objectif est de construire un IDS explicable sur NSL-KDD. Le projet ne se limite pas à entraîner un modèle de classification. Nous devons aussi expliquer les décisions, évaluer la stabilité des explications, analyser les risques de sécurité et tester des attaques adversariales ainsi que des défenses.

## 2. Pourquoi NSL-KDD?

NSL-KDD est le dataset demandé dans le sujet et c'est un benchmark connu en détection d'intrusions. Il a l'avantage d'avoir des splits train/test standardisés. Sa limite principale est qu'il est ancien et ne représente pas parfaitement le trafic réseau moderne.

## 3. Pourquoi ne pas utiliser uniquement l'accuracy?

L'accuracy peut être trompeuse avec un dataset déséquilibré. Un modèle peut avoir une bonne accuracy tout en ratant des attaques rares. C'est pour cela que nous utilisons F1, PR-AUC, balanced accuracy et rappel par famille d'attaque.

## 4. Pourquoi R2L et U2R sont difficiles?

R2L et U2R sont rares et plus subtils que DoS ou Probe. Ils peuvent ressembler davantage à du trafic normal. C'est pour cela que le rappel par famille est important: il montre si le modèle détecte aussi les attaques rares, et pas seulement les familles faciles.

## 5. Pourquoi Adv+ExtraTrees est le modèle final?

Adv+ExtraTrees donne le meilleur compromis. Il obtient un F1 binaire de 0.9063, un PR-AUC de 0.9626 et une balanced accuracy de 0.9064. Il améliore aussi la détection des familles rares et montre une très bonne défense contre transfer-PGD dans les tests.

## 6. Pourquoi Security-OR n'est pas le modèle principal?

Security-OR est plus strict et obtient 0.00% d'évasion transfer-PGD dans les tests, mais son F1 propre est plus faible: 0.8796 contre 0.9063 pour Adv+ExtraTrees. Il est donc intéressant comme mode de haute sécurité, mais pas comme modèle par défaut.

## 7. Que signifie PR-AUC?

PR-AUC mesure la qualité du compromis précision-rappel sur plusieurs seuils. En IDS, c'est utile car le choix du seuil dépend du coût des faux positifs et des faux négatifs.

## 8. Quelle est la différence entre classification binaire et classification par famille?

La classification binaire décide si le trafic est normal ou malveillant. La classification par famille cherche à distinguer DoS, Probe, R2L et U2R. La décision binaire correspond à l'alerte IDS, tandis que l'analyse par famille permet de comprendre quels types d'attaques sont détectés ou manqués.

## 9. Comment ce projet se relie au deep learning vu en cours?

Le cours explique que le deep learning apprend des représentations automatiquement. Dans notre projet, le Torch MLP apprend des combinaisons non linéaires des 478 features. Mais comme NSL-KDD est tabulaire, nous combinons aussi des modèles classiques à arbres et des features dérivées.

## 10. Pourquoi utiliser un MLP?

Un MLP est adapté à un vecteur tabulaire. Il peut apprendre des relations non linéaires entre les variables grâce aux couches cachées et aux fonctions d'activation. Il est aussi différentiable, ce qui permet d'utiliser Integrated Gradients et PGD.

## 11. Pourquoi ne pas utiliser un CNN?

Les CNN sont adaptés aux images ou aux grilles, car ils exploitent la localité spatiale avec des filtres, des feature maps, du stride et du pooling. NSL-KDD est un dataset tabulaire, sans voisinage spatial naturel entre les colonnes. Un CNN serait donc moins justifié.

## 12. Peut-on quand même utiliser un CNN sur NSL-KDD?

Techniquement oui, en transformant le vecteur de features en pseudo-image. Mais cela impose une structure spatiale artificielle. Sans justification forte de l'ordre des features, un MLP ou des arbres sont plus défendables.

## 13. Pourquoi ne pas utiliser un RNN ou LSTM?

Les RNN et LSTM sont faits pour des séquences ordonnées avec une mémoire d'état caché. NSL-KDD contient des enregistrements de connexions indépendants, pas des séquences temporelles complètes. Un RNN serait plus logique si nous avions des sessions ou des flux ordonnés.

## 14. Les transformers auraient-ils été utiles?

Les transformers sont très forts pour les séquences grâce à l'attention, avec queries, keys et values. Ici, l'entrée est un vecteur tabulaire fixe, pas une longue séquence de tokens. Un transformer ajouterait de la complexité sans avantage clair pour ce dataset.

## 15. Quel est le rôle des fonctions d'activation?

Les fonctions d'activation introduisent la non-linéarité. Sans elles, plusieurs couches linéaires se réduisent à une seule transformation linéaire. Dans notre MLP, elles permettent d'apprendre des frontières de décision complexes entre trafic normal et attaque.

## 16. Pourquoi ReLU est souvent utilisée?

ReLU est efficace et réduit mieux le problème de vanishing gradient que sigmoid ou tanh dans les couches cachées. C'est une fonction standard pour entraîner des réseaux plus rapidement et de façon plus stable.

## 17. Quelle loss est utilisée pour un IDS binaire?

Pour une décision binaire normal/attaque, la loss naturelle est la binary cross-entropy. Elle pénalise les probabilités mal calibrées pour les deux classes.

## 18. Pourquoi la cross-entropy plutôt que MSE?

MSE est surtout adaptée à la régression ou à la reconstruction, par exemple dans les autoencodeurs. Pour la classification, la cross-entropy est plus adaptée car elle optimise directement les probabilités de classes.

## 19. Comment la backpropagation intervient dans le projet?

La backpropagation entraîne les modèles Torch en calculant les gradients de la loss par rapport aux poids. Elle intervient aussi indirectement dans les attaques PGD, où les gradients sont utilisés par rapport aux entrées pour créer des exemples adversariaux.

## 20. Comment PGD est lié à la descente de gradient?

La descente de gradient modifie les poids pour réduire la loss. PGD utilise l'idée inverse du point de vue sécurité: il modifie l'entrée pour pousser le modèle vers une mauvaise décision. Les gradients deviennent donc un outil d'attaque.

## 21. Pourquoi les mini-batches sont utiles?

Les mini-batches donnent un compromis entre stabilité et efficacité. Ils permettent d'utiliser le GPU efficacement tout en évitant certains problèmes d'une descente de gradient trop déterministe.

## 22. Qu'est-ce que TreeSHAP?

TreeSHAP est une méthode d'explicabilité pour les modèles à arbres. Elle attribue à chaque variable une contribution dans la prédiction. Dans notre projet, elle sert à expliquer Random Forest, ExtraTrees et l'ensemble final.

## 23. Qu'est-ce que Integrated Gradients?

Integrated Gradients est une méthode pour expliquer les réseaux neuronaux. Elle intègre les gradients entre une entrée de référence et l'entrée réelle pour attribuer la prédiction aux variables.

## 24. Pourquoi utiliser SmoothIG?

SmoothIG lisse les Integrated Gradients en moyennant les attributions sur des versions bruitées de l'entrée. Cela réduit le bruit local des gradients et donne des explications plus stables.

## 25. Pourquoi les valeurs SHAP et SmoothIG ne sont pas comparables?

Elles n'ont pas la même unité. SHAP mesure des contributions dans un modèle à arbres, alors que SmoothIG mesure des magnitudes de gradients intégrés dans un réseau. Il faut comparer les classements et la cohérence des variables, pas les valeurs brutes.

## 26. Que signifie la stabilité des explications?

La stabilité signifie que les variables importantes restent similaires lorsque les observations sont proches ou lorsque les données sont rééchantillonnées. Une stabilité élevée rend les explications plus fiables pour un analyste.

## 27. Pourquoi la stabilité peut-elle être dangereuse?

Si les explications sont très stables, un attaquant peut identifier régulièrement les mêmes variables importantes et tenter de les manipuler. C'est le caractère dual de l'explicabilité.

## 28. Qu'est-ce qu'une attaque SHAP-guided?

C'est une attaque qui utilise les variables importantes selon SHAP pour modifier les features les plus influentes. Dans notre projet, cette attaque atteint jusqu'à 18.22% d'évasion contre Random Forest.

## 29. Qu'est-ce qu'une attaque IG-guided?

C'est une attaque qui utilise les attributions Integrated Gradients pour choisir quelles variables modifier dans le modèle neuronal. Elle atteint jusqu'à 15.97% d'évasion contre le Torch MLP.

## 30. Qu'est-ce que PGD full-feature?

PGD full-feature est une attaque white-box qui utilise les gradients pour modifier toutes les features normalisées. Elle est très forte, mais pas totalement réaliste car elle peut changer des variables catégorielles ou binaires.

## 31. Qu'est-ce que mutable-feature PGD?

Mutable-feature PGD est une attaque plus réaliste. Elle gèle les variables catégorielles et binaires et ne modifie que des variables continues liées au comportement réseau. Elle reste une attaque en espace de features, mais elle est plus défendable.

## 32. Pourquoi l'entraînement adversarial n'améliore pas tous les eps?

L'entraînement adversarial change la frontière de décision. Il peut améliorer la robustesse à certains budgets de perturbation tout en dégradant légèrement d'autres zones. C'est pour cela que nous montrons tous les eps, y compris le cas où la réduction est négative à eps 0.03 pour mutable PGD.

## 33. Quel est le meilleur résultat de défense?

Le meilleur résultat est la défense transfer-PGD de l'ensemble Adv+ExtraTrees. L'évasion du surrogate Torch est élevée, mais elle devient 0.50%, 0.00%, 0.00% et 0.00% sur l'ensemble final. Cela montre que les attaques se transfèrent mal.

## 34. Est-ce que 0.00% d'évasion signifie que le modèle est invulnérable?

Non. Cela signifie que nous n'avons observé aucune évasion dans les attaques et paramètres testés. Ce n'est pas une preuve certifiée. Un attaquant adaptatif différent pourrait être étudié dans des travaux futurs.

## 35. Quel est le lien avec les autoencodeurs vus en cours?

Les autoencodeurs peuvent être utilisés pour la détection d'anomalies: ils apprennent à reconstruire le trafic normal et signalent les entrées avec une forte erreur de reconstruction. Dans notre projet, nous avons utilisé un cadre supervisé car NSL-KDD fournit des labels.

## 36. Pourquoi ne pas utiliser un autoencodeur final?

Un autoencodeur est surtout utile quand les labels sont absents ou pour une approche non supervisée. Ici, nous avons des labels et nous devons évaluer précision, rappel, F1, PR-AUC et familles d'attaques. Les modèles supervisés sont donc plus directs.

## 37. Les GANs peuvent-ils aider ce projet?

Ils pourraient générer des exemples synthétiques pour les classes rares comme R2L et U2R. Mais les GANs sont difficiles à entraîner et peuvent produire des données peu réalistes. Pour un IDS, des données synthétiques non réalistes peuvent améliorer les scores sans améliorer la sécurité réelle.

## 38. Quelle est la différence entre attention et SHAP?

L'attention est un mécanisme interne des transformers qui mesure les interactions entre tokens avec queries, keys et values. SHAP est une méthode post-hoc qui explique la contribution des features à une prédiction. Les deux aident à interpréter, mais ils ne sont pas la même chose.

## 39. Que feriez-vous avec plus de temps?

Nous testerions le pipeline sur un dataset plus moderne comme CICIDS ou UNSW-NB15, nous ajouterions des attaques adaptatives black-box, et nous étudierions des attaques plus réalistes au niveau flux ou paquets réseau.

## 40. Quelle est la phrase finale à retenir?

Le modèle Adv+ExtraTrees n'est pas présenté comme parfaitement robuste, mais il offre le meilleur équilibre testé entre performance IDS, détection des familles rares, explicabilité, stabilité et robustesse empirique contre les attaques évaluées.
