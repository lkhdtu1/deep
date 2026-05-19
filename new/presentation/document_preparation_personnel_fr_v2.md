# Document Personnel De Preparation V2 - Projet 5 IDS Explicable

Ce document est la version clarifiee pour preparer la soutenance. Il garde volontairement plusieurs termes en anglais, parce que ce sont les termes utilises en Machine Learning, en XAI et en cybersecurite: `features`, `preprocessing`, `train/test split`, `precision`, `recall`, `F1`, `PR-AUC`, `threshold`, `TreeSHAP`, `Integrated Gradients`, `SmoothIG`, `PGD`, `evasion`, `transfer`, `ensemble`, `baseline`.

L'objectif est que tu puisses repondre a une question du jury sans seulement memoriser des phrases. Il faut comprendre ce que chaque element signifie, pourquoi il est la, comment on l'a obtenu, et quelles limites il faut reconnaitre.

## 1. Le Projet En Une Vision Simple

Le projet consiste a construire un IDS, c'est-a-dire un Intrusion Detection System. Un IDS observe des connexions reseau et decide si elles sont normales ou malveillantes. Dans notre cas, la decision principale est binaire: `normal` ou `attack`.

Mais le projet ne demande pas seulement de faire une classification. Le vrai coeur du sujet est l'IDS explicable. Cela veut dire que le modele doit etre accompagne d'une analyse qui repond a trois questions:

- Pourquoi le modele a-t-il predit `attack`?
- Est-ce que cette explication est stable ou change-t-elle facilement?
- Est-ce qu'un attaquant peut utiliser cette explication pour contourner l'IDS?

Notre pipeline repond a ces questions en cinq grandes etapes: preprocessing, training, explainability, adversarial attacks, defenses.

La conclusion generale est la suivante: le modele final `Adv+ExtraTrees Ensemble IDS` donne le meilleur compromis teste entre performance IDS, detection des familles rares, explainability, stability et robustness contre les attaques evaluees. Il n'est pas presente comme invulnerable.

## 2. Dataset NSL-KDD

NSL-KDD est le dataset impose par le sujet. Il contient des enregistrements de connexions reseau. Chaque ligne represente une connexion avec des informations comme le protocole, le service, le flag de connexion, des compteurs, des bytes, des taux d'erreur, etc.

Dans nos resultats:

- KDDTrain+ contient 125,973 lignes.
- KDDTest+ contient 22,544 lignes.
- Apres preprocessing, on obtient 478 features.

Le dataset contient des attaques regroupees en familles:

- `DoS`: attaques de type Denial of Service.
- `Probe`: reconnaissance, scan, exploration du reseau.
- `R2L`: Remote to Local, tentative d'acces local depuis l'exterieur.
- `U2R`: User to Root, tentative d'escalade de privileges.
- `normal`: trafic non malveillant.

DoS et Probe sont generalement plus faciles car ils creent souvent des patterns visibles: volume, repetition, scan, erreurs. R2L et U2R sont plus difficiles car ils sont rares et souvent plus proches du trafic normal.

## 3. Preprocessing: Ce Qu'on A Fait Exactement

Le preprocessing transforme les donnees brutes en une matrice numerique que les modeles peuvent utiliser. C'est une etape critique parce qu'un mauvais preprocessing peut donner des resultats artificiellement bons ou introduire du data leakage.

### 3.1 Lecture Des Donnees

On charge les fichiers NSL-KDD train et test. Les lignes contiennent les features originales et le label d'attaque. Le label original peut etre `normal`, `neptune`, `smurf`, `guess_passwd`, etc. Ces labels detailles sont ensuite regroupes en familles.

### 3.2 Mapping Des Labels

On cree deux types de labels.

Le premier est un label binaire:

- `0` pour normal
- `1` pour attack

Ce label sert aux modeles IDS binaires. C'est le plus proche d'une alerte IDS reelle: est-ce que je declenche une alerte ou non?

Le deuxieme est un label de famille:

- `normal`
- `DoS`
- `Probe`
- `R2L`
- `U2R`

Ce label sert a analyser le comportement du modele par type d'attaque. Il permet de voir si le modele detecte seulement les attaques faciles ou aussi les attaques rares.

### 3.3 Encodage Des Features Categorielles

Certaines features sont categorielles, par exemple:

- `protocol_type`: tcp, udp, icmp
- `service`: http, private, ftp, smtp, etc.
- `flag`: SF, S0, REJ, etc.

Les modeles ne peuvent pas utiliser directement des chaines de caracteres. On applique donc un `one-hot encoding`. Exemple:

`protocol_type = tcp` devient:

- `protocol_type_tcp = 1`
- `protocol_type_udp = 0`
- `protocol_type_icmp = 0`

Pourquoi one-hot? Parce qu'il evite de donner un ordre artificiel aux categories. Si on codait tcp = 1, udp = 2, icmp = 3, le modele pourrait croire que icmp est "plus grand" que tcp, ce qui n'a pas de sens.

### 3.4 Transformation Des Features Numeriques

Certaines variables numeriques ont des valeurs tres grandes ou tres asymetriques, par exemple `src_bytes` et `dst_bytes`. Des transformations comme le log peuvent rendre ces distributions plus faciles a apprendre.

On utilise aussi une mise a l'echelle, surtout utile pour les modeles neuronaux. Un MLP apprend mieux si les features sont sur des echelles comparables. Sinon, une feature avec de grandes valeurs numeriques peut dominer les gradients.

### 3.5 Feature Engineering

On ajoute des features derivees pour rendre certaines relations plus visibles. Par exemple:

- `traffic_total_log`: resume du volume total de trafic.
- `byte_ratio`: relation entre bytes source et destination.
- `serror_gap`, `rerror_gap`, `host_serror_gap`, `host_rerror_gap`: differences ou ecarts entre taux d'erreurs.
- `same_diff_srv_gap`: relation entre comportements vers meme service et services differents.

Pourquoi ajouter ces features? Parce qu'en securite, certaines relations entre variables sont plus informatives que les variables separees. Par exemple, un volume de bytes seul est utile, mais le ratio entre bytes source et destination peut mieux indiquer un comportement anormal.

### 3.6 Alignement Train/Test

Le one-hot encoding peut creer des colonnes differentes si une categorie apparait dans test mais pas dans train, ou inversement. Il faut donc aligner les colonnes train et test pour avoir exactement les memes features dans le meme ordre.

Apres tout cela, on obtient:

- `X_train`: 125,973 lignes et 478 features.
- `X_test`: 22,544 lignes et 478 features.

## 4. Pourquoi Le Preprocessing Est Important

Sans preprocessing, les modeles ne comprendraient pas correctement les variables categorielles. Sans scaling, les modeles neuronaux peuvent etre instables. Sans feature engineering, certaines relations reseau importantes resteraient moins visibles. Sans alignement train/test, le modele pourrait recevoir des colonnes incoherentes entre entrainement et test.

Le preprocessing est donc une partie du modele. Il ne faut pas le presenter comme une simple etape technique secondaire.

## 5. Les Modeles: Ce Qu'ils Sont Et Comment On Les A Obtenus

Les noms des modeles peuvent sembler abstraits. Cette section explique chaque modele simplement.

### 5.1 Logistic Regression

`Logistic Regression` est une baseline lineaire. Elle apprend une combinaison ponderee des features pour separer normal et attack, ou les familles d'attaque selon la version.

Pourquoi l'utiliser? Parce qu'il faut une baseline simple. Si un modele complexe ne fait pas mieux qu'une Logistic Regression, sa complexite n'est pas justifiee.

Comment on l'obtient? On l'entraine sur les features preprocessées, puis on choisit ses hyperparametres simples, par exemple `C`, sur validation. Dans nos resultats, elle donne un F1 binaire de 0.8344.

### 5.2 Random Forest

`Random Forest` est un ensemble de decision trees. Chaque arbre apprend des regles du type: si telle feature est superieure a telle valeur, aller a gauche, sinon aller a droite. La foret combine plusieurs arbres pour rendre la prediction plus stable.

Pourquoi l'utiliser? Les arbres sont tres bons sur les donnees tabulaires. Ils capturent des relations non lineaires sans necessiter un reseau profond.

Comment on l'obtient? On entraine plusieurs configurations et on selectionne celle qui marche le mieux en validation. Dans notre pipeline, la configuration selectionnee est autour de `n_estimators=320`, `max_depth=24`, `min_samples_leaf=2` pour la variation Random Forest multiclass.

### 5.3 ExtraTrees

`ExtraTrees`, ou Extremely Randomized Trees, ressemble a Random Forest mais ajoute plus de hasard dans le choix des splits. Cela peut augmenter la diversite entre arbres.

Pourquoi l'utiliser? Pour des donnees tabulaires, ExtraTrees peut etre tres robuste et rapide. La diversite des arbres peut aussi aider a eviter que le modele depende trop d'une seule frontiere de decision.

Dans notre projet, ExtraTrees est important parce qu'il sert de base a la composante robuste du modele final.

### 5.4 XGBoost

`XGBoost` est un modele de gradient boosting. Contrairement a Random Forest, ou les arbres sont relativement independants, XGBoost construit les arbres progressivement. Chaque nouvel arbre corrige les erreurs des arbres precedents.

Pourquoi l'utiliser? C'est une baseline forte pour les donnees tabulaires. Il sert a montrer que le modele final n'est pas compare seulement a des modeles faibles.

### 5.5 Torch MLP CUDA

`MLP` signifie Multi-Layer Perceptron. C'est un reseau neuronal fully connected. Chaque couche combine les features avec des poids, applique une activation non lineaire, puis transmet le resultat a la couche suivante.

Pourquoi l'utiliser? Le MLP peut apprendre des interactions non lineaires entre features. Il est aussi differentiable, donc on peut utiliser Integrated Gradients pour l'expliquer et PGD pour l'attaquer.

Pourquoi CUDA? Parce que l'entrainement du MLP est accelere par le GPU.

### 5.6 Torch Binary MLP

`Torch Binary MLP` est une version binaire du reseau neuronal. Il ne predit pas la famille d'attaque. Il predit seulement `normal` ou `attack`.

Pourquoi cette version? Parce que la decision IDS operationnelle principale est binaire: declencher une alerte ou non. Elle est aussi utile pour les attaques PGD, car une sortie binaire est plus simple a attaquer et a analyser.

Le threshold est important. Le modele sort un score ou une probabilite. Ensuite, on choisit un threshold: au-dessus du threshold, on dit attack; en dessous, on dit normal.

### 5.7 PGD-Adversarial Torch Binary MLP

Ce modele est le Torch Binary MLP apres `adversarial fine-tuning`. On prend le modele neuronal et on continue l'entrainement avec des exemples adversariaux generes par PGD.

Pourquoi? Pour apprendre au modele a resister a certaines perturbations. Si le modele voit pendant l'entrainement des attaques legerement modifiees, il peut apprendre une frontiere de decision moins fragile.

Limite: cela n'arrete pas toutes les attaques. A fort epsilon, le PGD direct reste tres puissant.

### 5.8 SHAP-Robust ExtraTrees

Ce modele est une version robuste de ExtraTrees. Il est obtenu avec une idee importante: utiliser SHAP pour savoir quelles features sont importantes, puis creer des exemples augmentes qui perturbent ces features importantes, et les ajouter a l'entrainement comme exemples d'attaque.

Le processus simplifie est:

1. Entrainer un modele arbre initial.
2. Utiliser TreeSHAP pour identifier les features importantes.
3. Generer des perturbations guidees par ces features.
4. Ajouter ces exemples adversariaux au train set avec le label attack.
5. Reentrainer ExtraTrees sur les donnees augmentees.

Pourquoi faire cela? Parce qu'on veut que le modele arbre apprenne a ne pas se laisser tromper par des modifications simples sur les features importantes.

### 5.9 Tuned Binary Ensemble

`Tuned Binary Ensemble` combine plusieurs modeles binaires: Logistic Regression, Random Forest, ExtraTrees, XGBoost et Torch Binary MLP. Il calcule une moyenne ponderee de leurs scores.

Pourquoi faire un ensemble? Parce que plusieurs modeles peuvent faire des erreurs differentes. Les combiner peut ameliorer la stabilite.

Limite: cet ensemble classique n'est pas le plus robuste adversarialement. Il est surtout utile comme comparaison.

### 5.10 Adv+ExtraTrees Ensemble IDS

C'est le modele final principal. Il combine:

- le `PGD-Adversarial Torch Binary MLP`, c'est-a-dire le modele neuronal fine-tuned avec PGD;
- le `SHAP-Robust ExtraTrees`, c'est-a-dire le modele arbre renforce par augmentation guidee par SHAP.

Dans les resultats, la combinaison utilise principalement la composante robuste ExtraTrees, avec des poids de type `adv=0.15` et `ret=0.85`, et un threshold final autour de 0.15.

Pourquoi cette combinaison? Parce que le reseau neuronal et les arbres n'ont pas la meme geometrie de decision. Les attaques PGD suivent les gradients du reseau, mais les arbres ne suivent pas cette meme frontiere differentiable. Cela aide a casser la transferabilite des attaques.

### 5.11 Security-OR

`Security-OR` est un mode optionnel plus strict. Ce n'est pas le modele final par defaut.

L'idee est la suivante: au lieu de faire seulement une moyenne ponderee douce, on signale une attaque si une composante forte du systeme est suffisamment confiante. C'est une logique proche de OR: si le modele adversarial ou le modele arbre robuste voit un risque fort, on peut declencher l'alerte.

Dans la pipeline, les scores des composantes sont calibres par rapport a leurs thresholds, puis combines sous forme de score strict. Le threshold Security-OR est ensuite choisi sur validation. Dans les resultats, le threshold est autour de 1.25.

Pourquoi Security-OR existe? Pour representer un mode haute securite. Si on veut minimiser les faux negatifs, on peut accepter plus d'alertes.

Pourquoi il n'est pas le modele final principal? Parce que son F1 propre est plus faible: 0.8796 contre 0.9063 pour Adv+ExtraTrees. Donc il est utile si les faux negatifs coutent tres cher, mais pas comme meilleur compromis general.

## 6. Comment Lire Les Resultats Des Modeles

Le modele final Adv+ExtraTrees obtient:

- F1 binaire: 0.9063
- PR-AUC: 0.9626
- Balanced accuracy: 0.9064
- DoS recall: 0.9859
- Probe recall: 1.0000
- R2L recall: 0.6786
- U2R recall: 0.8060

Cela signifie que le modele detecte tres bien DoS et Probe, et ameliore nettement R2L et U2R par rapport a plusieurs baselines. Il ne faut pas dire que R2L est parfait. Il faut dire que R2L reste difficile mais nettement ameliore.

## 7. Glossaire Rapide Des Metriques

`precision`: parmi les alertes attack, combien sont vraiment des attaques.

`recall`: parmi les vraies attaques, combien sont detectees.

`F1`: compromis entre precision et recall.

`PR-AUC`: qualite du ranking precision-recall sur plusieurs thresholds.

`balanced accuracy`: accuracy moyenne par classe, utile quand les classes sont desequilibrees.

`threshold`: seuil de decision. Si le score attack depasse ce seuil, on predit attack.

`evasion`: pourcentage d'attaques qui arrivent a passer comme normal apres perturbation.

`pp`: percentage points, ou points de pourcentage. Exemple: si l'evasion passe de 71.21% a 39.18%, la reduction absolue est 71.21 - 39.18 = 32.03 pp. Ce n'est pas la meme chose qu'une reduction relative en pourcentage.

## 8. Explainability: Pourquoi On L'utilise

L'explainability sert a repondre a la question: quelles features ont pousse le modele vers sa decision?

Dans un IDS, c'est essentiel. Un analyste ne veut pas seulement recevoir une alerte; il veut savoir si l'alerte repose sur des indices reseau plausibles: erreurs, service cible, login, flags de connexion, volume, repetition, etc.

L'explainability aide donc a:

- interpreter les alertes;
- verifier que le modele utilise des features logiques;
- detecter des comportements suspects du modele;
- comparer les modeles;
- etudier si les explications peuvent etre exploitees par un attaquant.

## 9. TreeSHAP Explique Simplement

TreeSHAP est une methode d'explication pour les modeles a arbres.

Idee intuitive: pour une prediction donnee, TreeSHAP distribue la responsabilite de la decision entre les features. Une feature avec une grande importance moyenne est une feature qui change fortement la sortie du modele.

Exemple simple: si un IDS predit attack principalement parce que `rerror_rate` est eleve et `same_srv_rate` est anormal, TreeSHAP va attribuer une contribution importante a ces features.

Dans notre projet, TreeSHAP est utilise pour Random Forest, ExtraTrees et l'ensemble final base sur arbres.

## 10. Integrated Gradients Explique Simplement

Integrated Gradients est une methode pour les reseaux neuronaux.

Un reseau neuronal est differentiable. On peut donc regarder comment la sortie change quand on modifie l'entree. Integrated Gradients part d'une entree de reference, souvent une baseline, puis va progressivement vers l'entree reelle. Il accumule les gradients le long de ce chemin.

Pourquoi faire cela? Parce qu'un gradient local seul peut etre bruyant. Integrated Gradients donne une attribution plus globale que le gradient instantane.

Exemple simple: si en passant d'une entree neutre a une connexion reelle, la feature `host_rerror_gap` augmente fortement le score attack, Integrated Gradients lui donnera une forte attribution.

## 11. SmoothIG Explique Simplement

SmoothIG est une version stabilisee d'Integrated Gradients.

On prend l'exemple a expliquer, on ajoute de petits bruits plusieurs fois, on calcule Integrated Gradients pour chaque version, puis on moyenne les resultats. Cela reduit les variations dues au bruit local du gradient.

Pourquoi c'est utile? Les reseaux neuronaux peuvent avoir des gradients instables. SmoothIG rend l'explication plus lisible et souvent plus stable.

## 12. Pourquoi SHAP Et SmoothIG N'ont Pas La Meme Echelle

C'est une question tres probable.

TreeSHAP et SmoothIG ne mesurent pas la meme chose.

TreeSHAP mesure une contribution dans l'echelle de sortie d'un modele arbre. SmoothIG mesure une magnitude d'attribution par gradients integres dans un reseau neuronal.

Donc une valeur SHAP de 0.02 peut etre importante, et une valeur SmoothIG de 6 peut aussi etre importante, mais on ne peut pas dire que 6 est 300 fois plus important que 0.02. Ce sont deux unites differentes.

La bonne reponse est: on compare les ranks, la coherence des top features, et la stability, pas les magnitudes brutes entre methodes.

## 13. Stability Des Explications

La stability mesure si les explications restent similaires.

`local Jaccard`: compare les ensembles de top features entre exemples proches. Si les memes features reviennent, Jaccard est eleve.

`local rank`: regarde si l'ordre des features reste similaire.

`bootstrap Jaccard`: verifie si les top features restent similaires quand on reechantillonne les donnees.

`bootstrap rank`: verifie si le ranking reste similaire sous reechantillonnage.

Resultats principaux:

- RF SHAP local Jaccard: 0.880
- Torch IG local Jaccard: 0.881
- SmoothIG local Jaccard: 0.899
- Adv+ExtraTrees local Jaccard: 0.845

Interpretation: les explications sont relativement stables. C'est bien pour la confiance analyste, mais cela peut aussi donner une cible stable a l'attaquant.

## 14. Attaques Guidees Par Les Explications

Une attaque guidee par explication utilise les features importantes pour modifier l'exemple.

`SHAP-guided evasion`: on attaque les features importantes selon SHAP.

`IG-guided evasion`: on attaque les features importantes selon Integrated Gradients.

Resultats:

- Best RF SHAP evasion: 18.22%
- Best Torch IG evasion: 15.97%
- Final ensemble TreeSHAP evasion: 0.00% sous les parametres testes

Interpretation: les explications peuvent aider a attaquer des modeles simples. L'ensemble final est beaucoup plus resistant a cette attaque precise.

## 15. PGD Explique Simplement

PGD signifie Projected Gradient Descent.

Dans l'entrainement normal, on utilise les gradients pour modifier les poids du modele et reduire la loss. Dans PGD adversarial, on utilise les gradients pour modifier l'entree et faire tromper le modele.

Processus:

1. On prend un exemple d'attaque detecte correctement.
2. On calcule dans quelle direction modifier les features pour reduire le score attack.
3. On applique une petite perturbation.
4. On limite la perturbation avec un budget `eps`.
5. On repete plusieurs iterations.

Si apres perturbation le modele predit normal, l'attaque a reussi: c'est une evasion.

## 16. Full-Feature PGD Vs Mutable-Feature PGD

`Full-feature PGD` peut modifier toutes les features normalisees. C'est tres fort, mais pas totalement realiste. Il peut modifier des colonnes one-hot, binaires ou categorielles d'une maniere qui ne correspond pas toujours a un vrai paquet reseau.

`Mutable-feature PGD` est plus realiste. Il bloque les features categorielles et binaires, puis modifie seulement les features continues. Cela reste une attaque tabulaire en espace de features, mais c'est plus defendable.

Dans nos resultats, le modele Torch seul est tres fragile au full-feature PGD. L'adversarial fine-tuning ameliore mutable-feature PGD surtout a eps 0.10 et eps 0.15.

## 17. Adversarial Fine-Tuning

Adversarial fine-tuning signifie qu'on continue l'entrainement du modele avec des exemples adversariaux.

Pourquoi? Pour apprendre au modele que certaines petites perturbations d'attaques doivent rester classees comme attack.

Dans notre pipeline, le Torch Binary MLP est fine-tuned avec des exemples PGD multi-epsilon. Cela aide, mais ne suffit pas contre toutes les attaques, surtout le PGD direct a fort budget.

## 18. Transfer-PGD

`Transfer-PGD` signifie que l'attaque est generee contre un modele surrogate, puis testee contre un autre modele.

Dans notre cas:

1. L'attaque est generee contre le modele Torch.
2. Les exemples adversariaux sont ensuite testes contre Adv+ExtraTrees.

Le terme `surrogate Torch` veut dire modele de substitution ou modele proxy. C'est le modele que l'attaquant utilise pour construire l'attaque. Ici, le surrogate est le modele Torch Binary MLP, parce qu'il est differentiable et donc attaquable avec PGD. Ensuite, on regarde si les exemples adversariaux produits contre ce surrogate arrivent aussi a tromper le modele final.

Pourquoi utiliser un surrogate? En pratique, un attaquant ne connait pas toujours exactement le modele deploye. Il peut entrainer ou utiliser un modele proche, l'attaquer, puis esperer que les exemples adversariaux se transferent vers le vrai IDS. C'est pour cela que `transfer-PGD` est une evaluation interessante: elle teste si une attaque construite sur un modele accessible fonctionne aussi contre un modele final different.

Exemple simple: imaginons qu'un attaquant ne connait pas notre ensemble Adv+ExtraTrees, mais qu'il sait entrainer un MLP similaire sur NSL-KDD. Il attaque son MLP avec PGD et obtient des exemples adversariaux. La question est: est-ce que ces exemples trompent aussi notre modele final? Dans nos resultats, la reponse est presque non, car l'evasion tombe a 0.50%, puis 0.00% pour les eps plus grands.

Resultat:

- Surrogate Torch evasion: 37.29%, 63.99%, 91.24%, 100.00%
- Final ensemble evasion: 0.50%, 0.00%, 0.00%, 0.00%

Interpretation: l'attaque suit la frontiere du reseau neuronal, mais ne se transfere pas bien vers l'ensemble final. C'est le meilleur resultat adversarial a defendre.

Il faut faire attention a la formulation. `Surrogate Torch evasion` ne veut pas dire que le modele final a cette evasion. Cela veut dire que les exemples generes contre Torch reussissent fortement contre Torch. Ensuite, quand on transfere ces memes exemples vers Adv+ExtraTrees, l'evasion devient presque nulle. C'est justement la preuve que la transferability est faible.

## 19. Pourquoi L'ensemble Final Resiste Mieux

L'ensemble final combine des modeles differents.

Le MLP est differentiable et donc vulnerable aux gradients.

ExtraTrees est non lineaire, tabulaire, et non differentiable de la meme maniere.

SHAP-Robust ExtraTrees a ete expose pendant l'entrainement a des perturbations guidees par features importantes.

La combinaison reduit la dependance a une seule frontiere de decision. C'est pour cela que les adversarial examples du Torch surrogate ne transferent pas bien.

## 19bis. Pourquoi On N'a Pas Choisi D'autres Modeles Comme KNN, SVM Ou Naive Bayes

Il est possible que le jury demande pourquoi nous n'avons pas teste KNN, SVM, Naive Bayes ou d'autres modeles classiques. La reponse doit etre pragmatique: nous n'avons pas choisi les modeles au hasard, nous avons choisi des modeles qui couvrent les besoins du sujet.

`KNN` classe un exemple en regardant les exemples d'entrainement les plus proches. Le probleme est que NSL-KDD apres preprocessing contient 125,973 exemples et 478 features. KNN peut devenir couteux en prediction, car il doit comparer un exemple test avec beaucoup d'exemples train. Il est aussi sensible au scaling et a la notion de distance dans un espace one-hot tres dimensionnel. Dans notre contexte, KNN n'apporte pas un avantage clair pour explainability ni pour adversarial analysis.

`SVM` peut etre fort, mais sur un dataset de cette taille et avec beaucoup de features one-hot, certains kernels peuvent etre couteux. Un SVM lineaire aurait ete proche d'une baseline lineaire comme Logistic Regression, tandis qu'un SVM non lineaire aurait ajoute du cout et moins de compatibilite avec nos objectifs XAI/adversarial. Il n'est pas impossible de l'utiliser, mais il n'etait pas prioritaire.

`Naive Bayes` repose sur une hypothese forte d'independance conditionnelle entre features. Or dans NSL-KDD, les features reseau sont souvent correlees: counts, rates, services, flags et erreurs se repondent. Naive Bayes serait une baseline tres simple, mais probablement trop faible et moins representative pour une defense IDS robuste.

`Neural networks plus profonds` auraient aussi ete possibles, mais le sujet impose une contrainte de training time et demande des modeles legers. Un modele plus profond peut surapprendre NSL-KDD sans forcement mieux generaliser sur KDDTest+.

`CNN`, `RNN` et `Transformer` ne sont pas le meilleur choix pour cette representation. CNN suppose une structure spatiale locale, RNN suppose une sequence temporelle, Transformer suppose une structure de tokens ou sequence avec attention. Notre entree est un vecteur tabulaire fixe de features de connexion. Un MLP et des modeles arbres sont plus coherents.

Donc, les modeles choisis couvrent deja les axes importants:

- Logistic Regression: baseline lineaire.
- Random Forest / ExtraTrees: modeles tabulaires forts et explicables avec TreeSHAP.
- XGBoost: boosting tabulaire fort.
- Torch MLP: modele differentiable pour Integrated Gradients et PGD.
- SHAP-Robust ExtraTrees et Adv+ExtraTrees: variations robustes et defendables pour le sujet.

Phrase courte a dire si on te pose la question: "Nous avons privilegie des modeles compatibles avec les donnees tabulaires, l'explicabilite et l'analyse adversariale. KNN ou SVM auraient pu etre ajoutes, mais ils n'apportaient pas autant a l'objectif central du projet."

## 20. Security-OR: Definition Et Obtention

Security-OR est un mode de decision strict.

Il est obtenu a partir des composantes deja entrainees, surtout le modele adversarial Torch et le modele robuste ExtraTrees. Au lieu de faire seulement une moyenne ponderee classique, on compare les scores des composantes a leurs thresholds calibres. Si une composante signale un risque fort, le score Security-OR augmente fortement.

Le nom OR vient de l'idee logique: alerter si au moins une composante forte voit un danger. Ce n'est pas exactement un OR binaire naïf, parce que les scores sont calibres et un threshold final est choisi, mais l'intuition est bien celle d'un mode strict.

Pourquoi on l'a cree? Pour avoir un mode haute securite. Il est utile quand on prefere generer plus d'alertes plutot que laisser passer une attaque.

Pourquoi il n'est pas le modele final? Parce que son F1 propre est plus faible. Adv+ExtraTrees donne 0.9063 F1, Security-OR 0.8796. Donc Security-OR est optionnel.

## 21. Que Veut Dire `pp`?

`pp` signifie percentage points, en francais points de pourcentage.

Exemple:

Si l'evasion passe de 71.21% a 39.18%, la reduction absolue est:

71.21 - 39.18 = 32.03 pp

Il ne faut pas confondre avec une reduction relative. Dire "32.03 pp" veut dire une difference directe entre deux pourcentages.

Autre exemple:

Si un modele passe de 80% a 90%, il gagne 10 pp. Mais en relatif, 10 points sur 80 correspond a 12.5% d'amelioration relative.

Dans notre rapport, les reductions de defense sont surtout donnees en `pp` parce que c'est plus clair pour comparer des taux d'evasion.

## 21bis. Stability: Pourquoi La Presentation Mentionne Surtout Local Jaccard

Dans la presentation, nous mentionnons surtout `local Jaccard` parce que la presentation doit rester courte. Une slide ne peut pas contenir toutes les metrics sans devenir illisible. `local Jaccard` est la plus facile a expliquer oralement: elle mesure si les top features restent les memes entre des exemples proches.

Ce n'est pas la seule metric calculee. Dans les resultats complets, nous avons aussi:

- `local rank`: verifie si l'ordre des features importantes reste similaire localement.
- `bootstrap Jaccard`: verifie si les top features restent similaires quand on reechantillonne les donnees.
- `bootstrap rank`: verifie si le ranking reste similaire sous reechantillonnage.

Pourquoi `local Jaccard` est suffisant pour la slide? Parce qu'il donne l'idee principale de stability de facon intuitive. Si les memes top features reviennent souvent, l'explication est plus stable. Pour une soutenance courte, il vaut mieux presenter une metric claire et bien l'expliquer que montrer quatre metrics sans analyse.

Mais si le jury demande: "Est-ce que vous avez mesure seulement local Jaccard?", il faut repondre non. La reponse correcte est:

"Dans la slide, nous avons affiche local Jaccard pour simplifier, car c'est la metric la plus intuitive. Mais dans le rapport et les resultats complets, nous avons aussi local rank, bootstrap Jaccard et bootstrap rank. Ces metrics confirment l'analyse de stability sous plusieurs angles."

Exemple simple de `local Jaccard`: supposons que l'explication A donne comme top features `{flag_SF, same_srv_rate, rerror_rate}` et l'explication B donne `{flag_SF, same_srv_rate, logged_in}`. Deux features sont communes sur quatre features distinctes au total, donc Jaccard = 2/4 = 0.5. Plus la valeur est proche de 1, plus les explications utilisent les memes top features.

Difference avec `rank`: Jaccard regarde surtout si les memes features sont presentes. Rank regarde aussi l'ordre. Si deux explications ont les memes features mais dans un ordre completement different, Jaccard peut etre eleve alors que rank stability est moins forte.

Difference avec `bootstrap`: local stability regarde des variations proches ou locales. Bootstrap stability regarde si les explications restent robustes quand on change l'echantillon de donnees. Cela donne une idee plus globale.

Dans nos resultats, les local Jaccard sont bons: RF SHAP 0.880, Torch IG 0.881, SmoothIG 0.899, final ensemble 0.845. Cela suffit pour dire a l'oral que les explications sont relativement stables, tout en gardant les autres metrics comme support si on te questionne.

## 22. Pourquoi Ne Pas Dire "Le Modele Est Parfait"?

Parce que ce serait faux et difficile a defendre.

0.00% evasion signifie 0.00% dans les conditions testees, pas dans toutes les conditions possibles.

Les limites principales:

- NSL-KDD est ancien.
- Les attaques feature-space ne sont pas toujours realistes au niveau paquet reseau.
- R2L reste difficile.
- Il n'y a pas de robustesse certifiee mathematiquement.
- Un attaquant adaptatif pourrait utiliser une autre strategie.

La bonne formulation est: "Le modele montre une forte robustesse empirique contre les attaques testees."

## 23. Mini-Reponses Pretes

Si on demande pourquoi plusieurs modeles: pour comparer une baseline, des modeles tabulaires forts, un modele neuronal differentiable, puis une defense ensemble.

Si on demande ce que veut dire surrogate Torch: c'est le modele Torch utilise comme modele de substitution pour generer les attaques PGD. Ensuite, on teste si ces attaques se transferent vers Adv+ExtraTrees.

Si on demande pourquoi pas CNN: NSL-KDD est tabulaire, pas spatial.

Si on demande pourquoi pas RNN: les lignes NSL-KDD ne sont pas des sequences temporelles completes.

Si on demande pourquoi pas Transformer: pas de sequence de tokens; complexite inutile pour ce dataset.

Si on demande pourquoi pas KNN: trop couteux et peu adapte a un espace one-hot de grande dimension; moins utile pour XAI et adversarial analysis.

Si on demande pourquoi pas SVM: possible, mais moins prioritaire; un SVM lineaire ressemble a une baseline lineaire, un SVM non lineaire peut etre couteux sur ce dataset.

Si on demande pourquoi seulement local Jaccard dans la slide: pour simplifier; les autres metrics existent dans les resultats complets.

Si on demande pourquoi SHAP et SmoothIG donnent des valeurs tres differentes: echelles differentes, on compare les ranks.

Si on demande ce que veut dire pp: points de pourcentage, difference absolue entre deux pourcentages.

Si on demande Security-OR: mode strict optionnel base sur les composantes calibrees; tres defensif mais F1 plus faible.

Si on demande le meilleur resultat: transfer-PGD, ou l'evasion passe de tres elevee sur Torch a presque zero sur Adv+ExtraTrees.

## 24. Resume Ultra-Clair Pour Toi

On part d'un dataset tabulaire NSL-KDD. On transforme les variables en features numeriques propres: one-hot, scaling, feature engineering. On entraine plusieurs modeles pour avoir baseline, variations, reseau neuronal et modeles arbres. On choisit Adv+ExtraTrees parce qu'il combine un modele neuronal adversarialement fine-tuned et un ExtraTrees robuste augmente par SHAP.

On explique les decisions avec TreeSHAP pour les arbres et IG/SmoothIG pour les reseaux. On verifie la stability des explications. Puis on montre que les explications peuvent guider des attaques. Le modele neuronal seul est fragile a PGD. Mais l'ensemble final casse la transferabilite: les attaques generees contre Torch ne fonctionnent presque plus contre Adv+ExtraTrees.

La conclusion defendable: notre IDS final est performant, explicable, relativement stable, et robuste empiriquement contre les attaques testees, tout en ayant des limites clairement annoncees.
