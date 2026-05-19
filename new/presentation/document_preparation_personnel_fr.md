# Document Personnel De Preparation - Projet 5 IDS Explicable

Ce document est fait pour comprendre le projet en profondeur avant la soutenance. Il ne doit pas etre lu tel quel pendant la presentation. Il sert a savoir exactement ce que signifient les concepts, pourquoi chaque choix a ete fait, comment interpreter les resultats, et comment repondre si le jury pose des questions techniques.

## 1. Idee Generale Du Projet

Le projet consiste a construire un systeme de detection d'intrusions, ou IDS, sur le dataset NSL-KDD. Un IDS analyse des connexions ou des flux reseau et decide si le comportement est normal ou malveillant. Dans notre cas, la decision principale est binaire: normal contre attaque. En plus, nous analysons les familles d'attaques: DoS, Probe, R2L et U2R.

La difficulte du projet ne vient pas seulement de la classification. Le sujet demande surtout un IDS explicable. Cela signifie qu'il ne suffit pas de dire "le modele predit attaque". Il faut aussi expliquer quelles variables ont conduit a cette prediction, verifier si ces explications sont stables, et discuter les implications de securite.

Le point de securite le plus important est le suivant: une explication peut aider un analyste, mais elle peut aussi aider un attaquant. Si l'explication dit que certaines features sont tres importantes, un attaquant peut essayer de modifier ces features pour contourner le detecteur. C'est pour cela que notre pipeline teste aussi des attaques guidees par les explications.

## 2. Dataset NSL-KDD

NSL-KDD est un dataset de detection d'intrusions derive de KDD Cup 99. Il contient des enregistrements de connexions reseau avec des variables numeriques et categorielles. Le split d'entrainement est KDDTrain+ et le split de test est KDDTest+.

Dans nos resultats, KDDTrain+ contient 125,973 exemples et KDDTest+ contient 22,544 exemples. Apres pretraitement, nous obtenons 478 features. Ce nombre est plus grand que le nombre de colonnes originales parce que les variables categorielles sont transformees par one-hot encoding.

Les familles d'attaques sont:

- DoS: Denial of Service. L'objectif est de rendre un service indisponible. Ces attaques produisent souvent des patterns de volume ou d'erreur plus visibles.
- Probe: reconnaissance ou scan. L'attaquant explore le reseau ou les services disponibles.
- R2L: Remote to Local. L'attaquant essaie d'obtenir un acces local depuis l'exterieur. Cette famille est difficile car elle peut ressembler a du trafic normal.
- U2R: User to Root. L'attaquant essaie d'obtenir des privileges root apres un acces utilisateur. Cette famille est rare et difficile.

Pourquoi R2L et U2R sont importants? Parce qu'un modele peut etre tres bon sur DoS et Probe mais tres mauvais sur R2L et U2R. Si on regarde seulement l'accuracy globale, on peut cacher cet echec. C'est pourquoi nous analysons le rappel par famille.

## 3. Pretraitement

Le pretraitement transforme les donnees brutes en un format exploitable par les modeles.

Les variables categorielles comme `protocol_type`, `service` et `flag` sont encodees avec one-hot encoding. Cela cree une colonne binaire pour chaque categorie possible. Par exemple, au lieu d'avoir une colonne `protocol_type` avec les valeurs tcp, udp ou icmp, on obtient des colonnes comme `protocol_type_tcp`, `protocol_type_udp` et `protocol_type_icmp`.

Les variables numeriques sont transformees ou normalisees pour que les modeles, surtout les reseaux neuronaux, puissent apprendre plus efficacement. Certaines variables liees aux bytes ou aux compteurs peuvent avoir des distributions tres asymetriques. Des transformations logarithmiques ou des ratios aident a mieux representer ces comportements.

Des features derivees sont ajoutees pour mieux capturer la logique reseau. Par exemple, des ratios de bytes, des totaux de trafic, ou des ecarts entre taux d'erreurs peuvent aider a detecter des comportements anormaux.

Pourquoi ne pas utiliser seulement les features originales? Parce que les features derivees donnent au modele des signaux plus directement utiles. En securite, certaines relations entre variables sont plus informatives que les variables brutes separees.

## 4. Modeles Utilises

Nous utilisons plusieurs modeles parce que le sujet demande une baseline et plusieurs variations, mais aussi parce que differents modeles ont differents avantages.

Logistic Regression est une baseline simple et interpretable. Elle est utile pour avoir un point de comparaison. Si un modele plus complexe ne fait pas mieux qu'une regression logistique, il n'est pas justifie.

Random Forest et ExtraTrees sont des ensembles d'arbres. Ils sont souvent tres forts sur les donnees tabulaires. Ils capturent des relations non lineaires et des interactions entre features sans necessiter une architecture deep learning lourde.

XGBoost est un modele boosting performant pour les donnees tabulaires. Il sert comme autre variation forte.

Torch MLP est un reseau neuronal fully connected. Il est utile car il apprend des combinaisons non lineaires, et surtout parce qu'il est differentiable. Cela permet d'utiliser Integrated Gradients pour l'explication et PGD pour les attaques adversariales.

Adv+ExtraTrees Ensemble est le modele final. Il combine une partie neuronale adversarialement fine-tuned et une partie ExtraTrees robuste. L'objectif est de beneficier a la fois de l'apprentissage neuronal et de la robustesse des arbres sur donnees tabulaires.

## 5. Pourquoi Pas CNN, RNN Ou Transformer?

Un CNN est adapte aux images ou aux donnees en grille. Il utilise des filtres locaux, des feature maps, du padding, du stride et du pooling. NSL-KDD est un vecteur tabulaire, pas une image. Les colonnes voisines n'ont pas forcement une relation spatiale. Un CNN serait donc moins naturel.

Un RNN ou LSTM est adapte aux sequences temporelles. Il garde un etat cache pour memoriser le passe. NSL-KDD contient des connexions individuelles, pas des sequences completes ordonnees dans le temps. Si nous avions des sessions reseau ou des logs ordonnes, un RNN pourrait etre justifie.

Un transformer est adapte aux sequences de tokens et utilise l'attention avec queries, keys et values. Il serait utile pour des logs, du texte, ou des flux sequentiels. Pour un vecteur tabulaire fixe, il ajoute de la complexite sans avantage clair.

Donc le choix MLP + arbres est plus coherent avec la nature du dataset.

## 6. Metriques De Performance

Precision mesure parmi les alertes attaque combien sont vraiment des attaques. Une precision faible signifie beaucoup de faux positifs.

Recall mesure parmi les attaques reelles combien sont detectees. Un recall faible signifie beaucoup de faux negatifs. En securite, les faux negatifs sont dangereux parce qu'une attaque passe inaperçue.

F1 est la moyenne harmonique entre precision et recall. C'est utile quand on veut equilibrer les deux.

PR-AUC mesure la qualite du classement precision-rappel sur plusieurs seuils. C'est important en IDS parce que le seuil peut etre ajuste selon le contexte operationnel.

Balanced accuracy moyenne la performance par classe et evite que la classe majoritaire domine le score.

Family recall mesure le rappel pour DoS, Probe, R2L et U2R. C'est essentiel pour ne pas cacher une mauvaise detection des familles rares.

## 7. Resultats Propres Principaux

Le modele final Adv+ExtraTrees obtient:

- Binary F1: 0.9063
- PR-AUC: 0.9626
- Balanced accuracy: 0.9064
- DoS recall: 0.9859
- Probe recall: 1.0000
- R2L recall: 0.6786
- U2R recall: 0.8060

L'analyse est que le modele est tres fort sur DoS et Probe, et nettement meilleur que les baselines sur R2L et U2R. Il ne resout pas parfaitement R2L, mais il ameliore fortement le comportement rare-family par rapport a des modeles plus faibles.

## 8. Explicabilite: Pourquoi Et Comment?

L'explicabilite sert a comprendre pourquoi le modele declenche une alerte. Dans un contexte IDS, c'est important parce qu'un analyste doit pouvoir verifier si l'alerte semble logique.

Nous utilisons plusieurs methodes:

TreeSHAP explique les modeles a arbres. Il attribue une contribution a chaque feature. Une contribution positive peut pousser vers attaque, une contribution negative peut pousser vers normal selon la convention du modele.

Integrated Gradients explique les reseaux neuronaux. Il calcule comment la sortie change quand on passe progressivement d'une entree de reference a l'entree reelle. Cela attribue la prediction aux features.

SmoothIG est une version lisse d'Integrated Gradients. On ajoute de petites perturbations bruitees a l'entree, on calcule Integrated Gradients plusieurs fois, puis on moyenne. Cela reduit le bruit local des gradients.

Pourquoi plusieurs methodes? Parce que les arbres et les reseaux neuronaux n'ont pas la meme structure. Utiliser TreeSHAP pour les arbres et IG/SmoothIG pour les reseaux est plus correct que forcer une seule methode partout.

## 9. Attention A La Comparaison SHAP Et SmoothIG

Ne jamais comparer directement les valeurs brutes de SHAP et SmoothIG.

Une moyenne SHAP autour de 0.02 peut etre importante dans un modele arbre. SmoothIG peut afficher 5 ou 6 parce que l'echelle vient des gradients integres du reseau. Les deux nombres ne sont pas dans la meme unite.

La bonne comparaison est:

- Dans chaque graphique, quelles sont les features top?
- Ces features ont-elles un sens en securite reseau?
- Les top features restent-elles stables?
- Les methodes differentes racontent-elles une histoire compatible?

Si le jury demande pourquoi SmoothIG est beaucoup plus grand que SHAP, repondre: "Ce sont des echelles d'attribution differentes. SHAP mesure une contribution moyenne dans un modele arbre, SmoothIG mesure une magnitude de gradients integres dans un reseau neuronal. On compare les rangs et la coherence, pas les valeurs brutes."

## 10. Features Importantes Et Sens Securite

Les features importantes du modele final incluent `flag_SF`, `same_srv_rate`, `dst_host_srv_count`, `logged_in`, `dst_host_same_srv_rate`, `rerror_rate`, `dst_host_rerror_rate`, `service_private`, `same_diff_srv_gap` et `dst_host_srv_serror_rate`.

`flag_SF` correspond a un etat de connexion reussie. C'est utile parce que certains comportements normaux ont des connexions reussies regulieres, tandis que certaines attaques provoquent des flags differents ou des erreurs.

`same_srv_rate` et `dst_host_same_srv_rate` mesurent la concentration de connexions vers le meme service. C'est utile pour detecter des scans, des comportements repetitifs ou des tentatives ciblees.

`dst_host_srv_count` mesure le nombre de connexions vers un service cote hote. Cela capture des patterns au niveau de la destination.

`logged_in` est important pour distinguer certains comportements authentifies et non authentifies.

`rerror_rate` et `dst_host_rerror_rate` capturent les erreurs de connexion. Des taux d'erreurs eleves peuvent indiquer des tentatives anormales, des scans ou des attaques.

Ces features sont defendables car elles correspondent a des comportements reseau reels, pas a des artefacts incomprehensibles.

## 11. Stabilite Des Explications

Une explication stable signifie que les features importantes restent similaires quand l'entree change legerement ou quand l'echantillon d'analyse change.

Nous utilisons local Jaccard, local rank correlation, bootstrap Jaccard et bootstrap rank. Le Jaccard compare des ensembles de top features. Si deux explications ont presque les memes top features, le Jaccard est eleve. La correlation de rang regarde si l'ordre des features reste similaire.

Resultats importants:

- RF SHAP local Jaccard: 0.880
- Torch IG local Jaccard: 0.881
- SmoothIG local Jaccard: 0.899
- Ensemble final local Jaccard: 0.845

Ces valeurs montrent que les explications sont relativement stables. Cela aide l'analyste, mais cela peut aussi aider l'attaquant. C'est le lien direct entre stabilite et securite.

## 12. Attaques Guidees Par Explication

Une attaque guidee par explication utilise les features indiquees comme importantes pour modifier l'exemple.

SHAP-guided evasion: on utilise SHAP pour savoir quelles features influencent le modele arbre, puis on modifie ces features dans une direction qui reduit la detection.

IG-guided evasion: on utilise Integrated Gradients pour savoir quelles features influencent le MLP, puis on modifie ces features.

Resultats:

- Best RF SHAP evasion: 18.22%
- Best Torch IG evasion: 15.97%
- Final ensemble TreeSHAP evasion: 0.00% sous les parametres testes

Analyse: les explications peuvent bien guider des attaques contre des modeles simples, mais l'ensemble final est plus resistant dans ce scenario.

## 13. PGD

PGD signifie Projected Gradient Descent. C'est une attaque iterative. A chaque iteration, on calcule le gradient de la loss par rapport a l'entree, on modifie l'entree dans une direction adversariale, puis on projette la perturbation pour rester dans un budget epsilon.

Dans notre projet, PGD attaque le modele neuronal parce qu'il est differentiable. Les arbres ne sont pas differentiables de la meme maniere, donc on ne les attaque pas directement avec PGD standard.

Full-feature PGD peut modifier toutes les features normalisees. C'est tres fort, mais peu realiste.

Mutable-feature PGD gele les variables categorielles et binaires et modifie seulement des variables continues. C'est plus realiste, mais toujours une attaque en espace de features, pas une generation de vrais paquets reseau.

## 14. Entrainement Adversarial

L'entrainement adversarial consiste a creer des exemples adversariaux pendant l'entrainement et a les ajouter pour rendre le modele moins fragile. L'idee est d'apprendre une frontiere de decision plus robuste.

Dans notre pipeline, le Torch Binary MLP est fine-tuned avec des exemples PGD multi-epsilon. Cela l'aide a resister a certaines perturbations, surtout dans mutable-feature PGD aux budgets moyens et eleves.

Mais l'entrainement adversarial ne resout pas tout. A eps eleve, le PGD direct reste fort. C'est normal: une attaque white-box avec un grand budget est tres difficile a bloquer sans garantie certifiee.

## 15. Transfer-PGD

Transfer-PGD est different du PGD direct. Dans PGD direct, l'attaquant attaque le modele cible exact. Dans transfer-PGD, l'attaquant genere les exemples adversariaux contre un modele surrogate, puis teste si ces exemples trompent un autre modele.

Pourquoi c'est important? Parce qu'en realite, l'attaquant ne connait pas toujours le modele deploye. Il peut attaquer un modele approximatif et esperer que les exemples se transferent.

Nos resultats montrent:

- Surrogate Torch evasion: 37.29%, 63.99%, 91.24%, 100.00%
- Ensemble final evasion: 0.50%, 0.00%, 0.00%, 0.00%

Analyse: les exemples adversariaux generes contre le reseau neuronal ne se transferent pas bien vers l'ensemble final. L'heterogeneite casse la transferabilite.

## 16. Pourquoi L'ensemble Final Fonctionne Mieux

L'ensemble final combine plusieurs idees:

- Une composante neuronale qui peut apprendre des relations non lineaires.
- Une composante ExtraTrees robuste qui est forte sur donnees tabulaires.
- Une augmentation adversariale guidee par SHAP pour apprendre a resister a certaines manipulations de features importantes.
- Une combinaison de modeles qui reduit la dependance a une seule frontiere de decision.

L'attaquant PGD suit les gradients du reseau neuronal. Mais l'ensemble final contient un modele arbre robuste qui ne suit pas la meme geometrie. Donc les exemples optimises pour le reseau ne trompent pas forcement l'ensemble.

## 17. Security-OR

Security-OR est un mode strict. Il declenche une alerte si l'une des composantes detecte fortement une attaque.

Avantage: tres bon contre transfer-PGD teste, avec 0.00% d'evasion.

Inconvenient: F1 propre plus faible, 0.8796 contre 0.9063 pour Adv+ExtraTrees. Cela peut signifier plus de faux positifs ou un moins bon equilibre global.

Conclusion: Security-OR est un mode optionnel pour contexte critique. Le modele par defaut reste Adv+ExtraTrees.

## 18. Limites A Connaitre Par Coeur

NSL-KDD est ancien et ne represente pas parfaitement le trafic moderne.

Les attaques en espace de features ne garantissent pas que les perturbations correspondent toujours a des paquets reseau realistes.

R2L et U2R restent difficiles, meme si le modele final les ameliore.

0.00% d'evasion ne signifie pas invulnerable. Cela signifie 0.00% sous les attaques testees.

Il n'y a pas de robustesse certifiee mathematiquement.

## 19. Questions Difficiles Et Reponses Courtes

Si on demande pourquoi ne pas utiliser CNN: NSL-KDD est tabulaire, pas spatial. Les CNN supposent une localite entre voisins, comme les pixels.

Si on demande pourquoi ne pas utiliser RNN: les exemples NSL-KDD sont des connexions independantes, pas des sequences temporelles completes.

Si on demande pourquoi ne pas utiliser transformer: l'attention est utile pour des sequences de tokens, mais ici l'entree est un vecteur tabulaire fixe.

Si on demande pourquoi SHAP et SmoothIG ont des echelles differentes: SHAP est une contribution arbre; SmoothIG est une magnitude de gradients integres. On compare les rangs, pas les valeurs.

Si on demande si 0.00% veut dire invulnerable: non, seulement sous le scenario teste.

Si on demande pourquoi Security-OR n'est pas choisi: il est plus strict mais son F1 propre est plus faible.

## 20. Resume Mental En 30 Secondes

Nous avons construit un IDS explicable sur NSL-KDD. Le modele final Adv+ExtraTrees obtient 0.9063 de F1, 0.9626 de PR-AUC et 0.9064 de balanced accuracy. Les explications montrent des features reseau logiques et relativement stables. Mais comme les explications peuvent guider des attaques, nous avons teste SHAP-guided evasion, IG-guided evasion, PGD, mutable-feature PGD et transfer-PGD. Le modele neuronal seul est fragile, mais l'ensemble final reduit fortement la transferabilite des attaques. La conclusion est que l'explicabilite doit etre accompagnee d'une analyse adversariale.
