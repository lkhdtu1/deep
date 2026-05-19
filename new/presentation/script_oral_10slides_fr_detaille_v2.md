# Script Oral Detaille V2 - Presentation 10 Slides

Ce script est la version adaptee du script oral detaille. Il garde certains termes en anglais quand ils sont plus naturels en Machine Learning et en cybersecurite: `features`, `preprocessing`, `baseline`, `recall`, `F1`, `PR-AUC`, `threshold`, `TreeSHAP`, `Integrated Gradients`, `SmoothIG`, `PGD`, `evasion`, `transfer`, `ensemble`.

Le but n'est pas de tout lire mot par mot. Le but est de parler avec precision et de montrer que vous comprenez la logique complete du projet: comment les donnees sont transformees, comment les modeles sont obtenus, pourquoi on utilise plusieurs methodes d'explicabilite, comment on mesure la stability, et pourquoi les defenses fonctionnent ou restent limitees.

## Slide 1 - Explainable IDS Under Adversarial Pressure

Bonjour. Nous sommes TAMIS Mohammed et GRYACH Ikram. Notre projet porte sur un IDS explicable, c'est-a-dire un systeme de detection d'intrusions qui ne donne pas seulement une prediction, mais qui permet aussi de comprendre les raisons de cette prediction.

Nous avons travaille sur le dataset NSL-KDD. Le modele final retenu est `Adv+ExtraTrees Ensemble IDS`. Il obtient un `F1` binaire de 0.9063 et un `PR-AUC` de 0.9626. Ces resultats montrent une bonne performance de detection, mais notre objectif va plus loin qu'un simple score.

Dans ce projet, nous analysons quatre aspects: la performance IDS, l'explicabilite des decisions, la stability des explications, et la resistance aux attaques adversariales. Le resultat de defense le plus fort est observe avec `transfer-PGD`: des exemples adversariaux generes contre le modele Torch ne se transferent presque pas vers l'ensemble final. L'evasion devient 0.50% a eps 0.03, puis 0.00% a eps 0.06, 0.10 et 0.15.

Il faut formuler ce point correctement: nous ne disons pas que le modele est invulnerable. Nous disons qu'il est robuste empiriquement dans les scenarios d'attaque testes.

## Slide 2 - From Dataset To Defensible IDS Decision

Cette slide resume tout le process. On commence avec NSL-KDD: 125,973 records dans KDDTrain+ et 22,544 records dans KDDTest+. Apres `preprocessing`, on obtient 478 `features`.

Le `preprocessing` est important. D'abord, les labels d'attaque sont transformes en deux formes. La premiere est binaire: `normal` ou `attack`. C'est la decision IDS principale. La deuxieme est par famille: `normal`, `DoS`, `Probe`, `R2L`, `U2R`. Cette deuxieme vue sert a analyser si le modele detecte aussi les attaques difficiles et rares.

Ensuite, les features categorielles comme `protocol_type`, `service` et `flag` sont transformees avec `one-hot encoding`. Par exemple, au lieu de coder tcp, udp, icmp avec des nombres arbitraires, on cree des colonnes binaires. Cela evite de donner un ordre qui n'existe pas entre les categories.

Les features numeriques sont mises a l'echelle ou transformees pour etre plus utilisables par les modeles, surtout le MLP. Nous ajoutons aussi des features derivees, comme des ratios de bytes, des totaux de trafic et des gaps d'erreurs. Ces features donnent au modele des relations reseau plus informatives que les colonnes brutes seules.

Ensuite, nous entrainons plusieurs modeles, nous expliquons leurs decisions avec `TreeSHAP`, `Integrated Gradients` et `SmoothIG`, nous testons la stability des explications, puis nous attaquons et defendons les modeles. Chaque bloc correspond a une exigence du sujet: baseline, variations, metrics, explainability, stability, security analysis et reproducibility.

## Slide 3 - Best Default Model: Adv+ExtraTrees Ensemble

Cette slide explique pourquoi le modele final par defaut est `Adv+ExtraTrees Ensemble IDS`.

La `Logistic Regression` est notre baseline lineaire. Elle est simple et donne un point de comparaison. `Random Forest` et `ExtraTrees` sont des ensembles de decision trees, tres adaptes aux donnees tabulaires. `XGBoost` est un modele de boosting fort pour les donnees tabulaires. Le `Torch MLP` est un reseau neuronal fully connected: il apprend des relations non lineaires et il est differentiable, donc utile pour `Integrated Gradients` et `PGD`.

Le modele final combine deux idees. D'un cote, un `PGD-Adversarial Torch Binary MLP`, c'est-a-dire un MLP binaire fine-tuned avec des exemples adversariaux. De l'autre cote, un `SHAP-Robust ExtraTrees`, c'est-a-dire un ExtraTrees renforce avec des exemples augmentes guides par SHAP. La combinaison donne un modele plus robuste qu'un seul composant.

Les resultats propres du modele final sont: `F1` binaire 0.9063, `PR-AUC` 0.9626 et `balanced accuracy` 0.9064. Le modele detecte tres bien DoS et Probe, avec des `recall` de 0.9859 et 1.0000. Les familles R2L et U2R sont plus difficiles, mais le modele atteint 0.6786 de `recall` pour R2L et 0.8060 pour U2R. Il faut donc dire que R2L reste difficile, mais qu'il est nettement ameliore par rapport a plusieurs baselines.

La conclusion de cette slide est que le modele final est choisi comme meilleur compromis operationnel, pas seulement comme meilleur score isole.

## Slide 4 - Explanations Show Meaningful Network Evidence

Cette slide presente l'explication du modele final. Les top `features` incluent `flag_SF`, `same_srv_rate`, `dst_host_srv_count`, `logged_in`, `dst_host_same_srv_rate`, `rerror_rate`, `dst_host_rerror_rate` et d'autres variables liees aux erreurs et aux services.

Ces features sont logiques pour un IDS. `flag_SF` concerne l'etat de la connexion. `same_srv_rate` et `dst_host_same_srv_rate` montrent si les connexions se concentrent sur le meme service. `logged_in` donne une information sur l'authentification. Les features comme `rerror_rate` ou `dst_host_rerror_rate` indiquent des erreurs de connexion. Ces signaux peuvent correspondre a des scans, des tentatives d'acces, des anomalies ou des comportements malveillants.

Il faut aussi expliquer la question d'echelle. Une valeur `TreeSHAP` autour de 0.02 ou 0.05 peut etre importante dans un modele arbre. Une valeur `SmoothIG` peut etre autour de 5 ou 6 parce qu'elle vient de gradients integres dans un reseau neuronal. Ces valeurs ne sont pas dans la meme unite.

Donc, pendant l'oral, il ne faut pas comparer les magnitudes brutes entre SHAP et SmoothIG. Il faut comparer les `ranks`, la coherence des top features, et les metrics de stability.

## Slide 5 - Different Explainers, Same Security Story

Cette slide explique pourquoi nous utilisons plusieurs methodes d'explicabilite. Les modeles ne sont pas tous de meme nature, donc une seule methode ne serait pas suffisante.

`TreeSHAP` est utilise pour les modeles a arbres. Son role est de distribuer la contribution d'une prediction entre les features. Exemple simple: si le modele predit `attack` parce que `rerror_rate` est eleve et que le service cible est suspect, TreeSHAP donne une contribution importante a ces features.

`Integrated Gradients` est utilise pour les reseaux neuronaux. Un MLP est differentiable, donc on peut calculer comment la sortie change quand l'entree change. Integrated Gradients part d'une baseline et va progressivement vers l'exemple reel, en accumulant les gradients. Cela donne une attribution plus stable qu'un gradient instantane.

`SmoothIG` est une version plus stable d'Integrated Gradients. On ajoute de petits bruits a l'exemple, on calcule plusieurs Integrated Gradients, puis on moyenne. Cela reduit le bruit local du gradient et rend les explications plus lisibles.

La partie stability de la slide mesure si les explications restent similaires. `local Jaccard` compare les ensembles de top features. Si les memes features reviennent souvent, la valeur est elevee. Ici, RF SHAP obtient 0.880, Torch IG 0.881, SmoothIG 0.899 et l'ensemble final 0.845. Cela signifie que les explications sont relativement stables.

La conclusion est double. Pour un analyste, une explication stable est rassurante. Mais en securite, une explication stable peut aussi devenir un risque, parce qu'elle donne a l'attaquant une cible stable. C'est pourquoi la slide suivante teste les attaques guidees par explication.

## Slide 6 - Explanations Help Analysts, But Also Guide Evasion

Cette slide montre le caractere dual de l'explainability. Une explication sert a comprendre une alerte, mais elle peut aussi guider une attaque.

Dans `SHAP-guided evasion`, on utilise les features importantes selon SHAP pour savoir quelles variables modifier. L'idee est que si une feature influence fortement la prediction `attack`, alors la modifier dans le bon sens peut reduire le score attack. Contre Random Forest, la meilleure evasion observee atteint 18.22%.

Dans `IG-guided evasion`, on fait la meme chose mais avec les attributions d'Integrated Gradients sur le modele Torch MLP. Les gradients indiquent quelles features ont un effet important sur le score. La meilleure evasion observee atteint 15.97%.

Ces valeurs ne veulent pas dire que les modeles sont completement detruits. Elles montrent surtout que les explications peuvent etre exploitees. Une evasion de 18.22% signifie que, dans ce scenario d'attaque, une partie des attaques initialement detectees peut etre modifiee pour passer comme normal.

La troisieme figure montre que l'ensemble final resiste mieux a cette attaque guidee par TreeSHAP: l'evasion est 0.00% dans les parametres testes. Il faut dire "dans les parametres testes", pas "toujours". Cela montre que le modele final est mieux durci contre cette famille d'attaques, mais ce n'est pas une garantie universelle.

La phrase importante est: en cybersecurite, l'explicabilite n'est pas seulement un outil de transparence; c'est aussi une possible attack surface.

## Slide 7 - Neural IDS Alone Remains Vulnerable

Cette slide explique pourquoi le modele neuronal seul n'est pas suffisant.

`PGD` signifie Projected Gradient Descent. Dans l'entrainement normal, on utilise les gradients pour changer les poids du modele et reduire la loss. Dans une attaque PGD, on utilise les gradients pour changer l'entree et pousser le modele vers une mauvaise prediction. Ici, l'objectif de l'attaquant est de transformer une attaque detectee en exemple classe comme normal. Si cela reussit, c'est une `evasion`.

`Full-feature PGD` est tres fort parce qu'il peut modifier toutes les features normalisees. C'est un bon stress test, mais il n'est pas parfaitement realiste. Par exemple, il peut modifier des variables one-hot ou binaires d'une facon qui ne correspond pas forcement a un vrai paquet reseau.

Le resultat montre que le Torch Binary MLP original atteint 100% d'evasion sous full-feature PGD. Cela signifie qu'un reseau neuronal differentiable attaque directement par ses gradients peut etre tres fragile.

Pour une attaque plus realiste, nous utilisons `mutable-feature PGD`. Ici, les variables categorielles et binaires sont gelees. L'attaque ne modifie que des features continues, comme certains compteurs ou taux reseau. Ce n'est pas encore une simulation parfaite de trafic reel, mais c'est plus defendable qu'un PGD qui modifie tout.

L'adversarial fine-tuning aide surtout sur mutable-feature PGD aux budgets moyens et eleves. Par exemple, a eps 0.10, l'evasion passe de 71.21% a 39.18%, donc une reduction de 32.03 `pp`. Ici `pp` signifie percentage points, ou points de pourcentage. C'est une difference absolue: 71.21 moins 39.18. A eps 0.15, la reduction est de 42.03 pp.

La conclusion est que l'adversarial fine-tuning aide, mais ne suffit pas. Le modele neuronal seul reste trop vulnerable, donc le modele final doit utiliser un ensemble heterogene.

## Slide 8 - The Final Ensemble Breaks Transferability

Cette slide est la plus importante pour la partie defense.

`Transfer-PGD` signifie qu'on genere les adversarial examples contre un modele, appele `surrogate`, puis on teste ces exemples contre un autre modele. Dans notre cas, le surrogate est le modele Torch. Ensuite, les memes exemples sont testes sur Adv+ExtraTrees.

Pourquoi c'est important? Parce qu'en pratique, un attaquant ne connait pas toujours le modele final exact. Il peut attaquer un modele approximatif et esperer que les exemples se transferent vers le modele deploye. Si l'attaque se transfere, c'est dangereux. Si elle ne se transfere pas, c'est un bon signe de robustesse empirique.

Dans nos resultats, le surrogate Torch est fortement attaque: l'evasion est 37.29%, 63.99%, 91.24% et 100.00% selon eps. Mais sur l'ensemble final, l'evasion devient 0.50%, 0.00%, 0.00% et 0.00%. Les reductions sont donc 36.79 pp, 63.99 pp, 91.24 pp et 100.00 pp.

La raison principale est l'heterogeneite. Le PGD suit les gradients du reseau neuronal. Mais l'ensemble final contient aussi `SHAP-Robust ExtraTrees`, un modele arbre robuste dont la frontiere de decision n'est pas la meme que celle du reseau. Les adversarial examples optimises pour Torch ne sont donc pas forcement adversariaux pour l'ensemble final.

Il faut presenter ce resultat avec precision. On ne dit pas "notre modele bloque toutes les attaques". On dit: "dans le scenario transfer-PGD teste, l'ensemble final casse fortement la transferabilite des attaques generees contre Torch."

## Slide 9 - Security-OR Is Optional, Not The Main Claim

Cette slide clarifie `Security-OR`, parce que le nom peut porter a confusion.

`Security-OR` est un mode strict obtenu a partir des composantes deja entrainees. Les composantes principales sont le modele Torch adversarialement fine-tuned et le modele `SHAP-Robust ExtraTrees`. Au lieu de faire uniquement une moyenne ponderee classique, on compare les scores des composantes a leurs `thresholds` calibres. Si une composante est tres confiante qu'il y a une attaque, le systeme peut declencher une alerte. C'est l'intuition du OR logique: si au moins une composante forte voit un danger, on prend l'alerte au serieux.

Ce n'est pas un OR binaire naïf. Les scores sont calibres et un `threshold` final est choisi sur validation. Dans les resultats, Security-OR utilise un threshold autour de 1.25. Il obtient 0.00% d'evasion transfer-PGD dans les tests, ce qui est tres interessant pour un mode haute securite.

Mais Security-OR n'est pas le modele final par defaut, parce que son F1 propre est plus faible: 0.8796 contre 0.9063 pour Adv+ExtraTrees. Cela signifie que le mode strict peut sacrifier l'equilibre propre, probablement en augmentant les alertes ou en modifiant le compromis precision/recall.

La bonne position orale est donc: Security-OR est un mode optionnel pour un contexte critique, ou les faux negatifs coutent tres cher. Le modele principal reste Adv+ExtraTrees, parce qu'il donne le meilleur compromis general.

Il faut aussi rappeler les limites: NSL-KDD est ancien, les attaques feature-space ne sont pas exactement des attaques reseau reelles, R2L et U2R restent difficiles, et 0.00% d'evasion ne veut pas dire invulnerable.

## Slide 10 - What This Project Demonstrates

Pour conclure, il faut reconnecter la presentation aux livrables du sujet. Nous avons construit une pipeline reproductible qui entraine plusieurs modeles, compare une baseline et des variations, explique les decisions, mesure la stability des explications, teste les attaques guidees par explication, teste PGD, puis evalue des defenses.

Le modele final Adv+ExtraTrees obtient 0.9063 de F1 binaire, 0.9626 de PR-AUC, 0.9064 de balanced accuracy et 0.845 de local explanation stability. Il ameliore aussi la detection des familles difficiles, notamment U2R avec 0.806 de recall.

Le message final est que l'explainability est necessaire pour la confiance des analystes, mais qu'en cybersecurite elle doit aussi etre testee comme une attack surface. Les explications peuvent aider a comprendre les decisions, mais elles peuvent aussi guider des attaques. C'est pour cela que notre projet relie explainability, stability, evasion et defense.

La phrase finale a dire si on veut resumer: Adv+ExtraTrees n'est pas une defense universelle, mais c'est le meilleur compromis teste entre IDS performance, explainability, stability et robustness empirique sur NSL-KDD.

## Mini Glossaire A Retenir Pendant L'Oral

`features`: variables d'entree du modele.

`recall`: parmi les vraies attaques, proportion detectee par le modele.

`threshold`: seuil de decision utilise pour transformer un score en prediction.

`evasion`: attaque qui reussit a faire classer un exemple malveillant comme normal.

`pp`: percentage points, difference absolue entre deux pourcentages. Exemple: 71.21% - 39.18% = 32.03 pp.

`TreeSHAP`: explication adaptee aux modeles a arbres.

`SmoothIG`: Integrated Gradients lisse pour expliquer un reseau neuronal.

`PGD`: attaque iterative par gradients contre un modele differentiable.

`transfer-PGD`: attaque generee contre un surrogate, puis testee sur le modele final.

`Security-OR`: mode strict optionnel qui alerte si une composante calibree indique un risque fort.
