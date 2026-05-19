# Course-Adapted Oral Defense Q&A

This file adapts the Project 5 oral-defense questions to the concepts covered in the `cours/` PDFs: deep learning fundamentals, CNNs, RNNs, autoencoders, GANs, and transformers. The goal is to answer examiner questions using the vocabulary seen in class while keeping every answer connected to our IDS project.

## How To Answer In The Style Of The Course

When the examiner asks about the model, use the course language of representation learning. Say that deep learning moves from manual feature engineering to automatic feature extraction, but in this project we combine both: domain features from NSL-KDD preprocessing and learned representations from the Torch MLP.

When the examiner asks about training, use the course language of loss functions, gradient descent, backpropagation, learning rate, mini-batches, generalization, and regularization. Explain that the neural model is optimized with differentiable losses, while the tree models are trained with ensemble splitting rules and are not attacked directly with ordinary gradients.

When the examiner asks why we did not use CNN, RNN, or transformer architectures, connect the answer to data modality. CNNs are strongest for spatial grids and local patterns, RNNs are designed for ordered sequences with hidden state, and transformers are designed for attention over token sequences. NSL-KDD is a tabular flow dataset after preprocessing, so a tabular MLP and tree ensembles are more appropriate and lighter.

When the examiner asks about explainability, connect our work to the course's black-box and interpretability theme. The CNN course discussed Grad-CAM for visual focus areas; our equivalent is TreeSHAP for tree decisions and Integrated Gradients or SmoothIG for neural decisions.

When the examiner asks about anomaly detection, connect it to autoencoders. Autoencoders detect anomalies through high reconstruction error, but our main setting is supervised IDS because NSL-KDD provides labels. Autoencoders are a valid alternative or future extension, but the assignment asks us to train an IDS model and explain its decisions.

## Course-Based Questions And Answers

### 1. In class, deep learning was presented as automatic feature extraction. How does that appear in your project?

Deep learning performs automatic feature extraction by learning internal representations instead of relying only on manual rules. In our project, this appears in the Torch MLP, which learns nonlinear combinations of the 478 preprocessed features. However, because NSL-KDD is tabular and security-domain features are meaningful, we also keep engineered features such as byte ratios, traffic totals, and error-rate gaps. The final approach is therefore hybrid: engineered security features plus learned nonlinear representations.

### 2. Is this project classical machine learning or deep learning?

It uses both. Logistic Regression, Random Forest, ExtraTrees, and XGBoost are classical machine-learning models. The Torch MLP and Torch Binary MLP are deep-learning models because they use multiple layers, nonlinear activation functions, backpropagation, and gradient-based optimization. The final selected IDS is an ensemble that combines adversarial neural training with a robust ExtraTrees model.

### 3. Why did you use an MLP instead of a CNN?

CNNs are designed for grid-like inputs such as images, where local connectivity, convolution filters, feature maps, stride, padding, and pooling are useful. NSL-KDD is not an image dataset. After preprocessing, it is a tabular feature vector. There is no natural spatial neighborhood between features like there is between pixels. For that reason, an MLP and tree models are more appropriate than a CNN.

### 4. Could a CNN still be used on NSL-KDD?

Technically yes, if the feature vector is reshaped into a pseudo-image, but that would impose an artificial spatial structure on the features. The CNN course emphasized that CNNs exploit local spatial relationships and shared filters. Those assumptions are not naturally valid for NSL-KDD tabular features. A CNN would therefore be less justifiable unless we had a meaningful feature ordering or raw traffic representation.

### 5. Why did you not use an RNN or LSTM?

RNNs and LSTMs are designed for sequential data where the order of observations carries meaning. The RNN course emphasized hidden state, recurrence, BPTT, and long-term dependencies. Our input samples are independent NSL-KDD connection records, not ordered packet sequences or time-series sessions. Therefore, an RNN/LSTM would not match the data format unless we rebuilt the dataset as ordered network sessions.

### 6. Could RNNs improve this work in future?

Yes. If we had raw packet flows or ordered connection sessions, an RNN, GRU, LSTM, or transformer could model temporal dependencies between events. That would be closer to the RNN course examples of time series, speech, and sequence modeling. For this assignment, the fixed NSL-KDD tabular format makes a sequence model less natural.

### 7. Why did you not choose a transformer?

Transformers are powerful for sequences because self-attention lets tokens interact through queries, keys, and values. They are excellent for text and long-range dependencies, but our dataset is tabular and relatively small for transformer-style training. A transformer would add complexity and compute cost without a clear data-modality advantage. The assignment also limits experiments to reasonable training time, so a lighter tabular model is more defensible.

### 8. Can attention be useful for IDS?

Yes, attention can be useful if the IDS input is sequential, for example packet sequences, logs, or event streams. In that case, attention can show which time steps or events influence the alert. In our project, the closest equivalent is feature attribution rather than token attention: TreeSHAP, Integrated Gradients, SmoothIG, and final ensemble explanations show which features influence the IDS decision.

### 9. What is the role of activation functions in your neural model?

Activation functions introduce nonlinearity. The course emphasized that without nonlinear activation functions, stacked layers collapse into a linear model. Our MLP uses nonlinear hidden layers so it can learn complex boundaries between normal and attack traffic. For output behavior, binary IDS decisions use a sigmoid-like probability interpretation, while multiclass family prediction uses a softmax-style probability distribution.

### 10. Why is ReLU commonly used in hidden layers?

ReLU is efficient and helps reduce the vanishing-gradient problem compared with sigmoid or tanh in deep hidden layers. The course described ReLU as a practical default for hidden layers. In our project, using ReLU-style nonlinear layers helps the MLP learn nonlinear intrusion patterns while keeping training efficient on CUDA.

### 11. Why use sigmoid for binary IDS output?

Sigmoid maps the model output to a value between 0 and 1, which can be interpreted as an attack probability or attack score. Then we select a threshold to decide whether to raise an alert. This is why the report includes thresholds such as 0.15 for the final Adv+ExtraTrees ensemble.

### 12. Why is softmax relevant?

Softmax is relevant for multiclass classification because it converts raw logits into a probability distribution over classes. In our project, the family classifier predicts normal, DoS, Probe, R2L, and U2R. Softmax-like behavior is therefore appropriate for the multiclass Torch MLP.

### 13. Which loss functions relate to this project?

For binary IDS, the relevant loss is binary cross-entropy because the output is attack versus normal. For multiclass family detection, the relevant loss is cross-entropy over the five families. This matches the course distinction between regression losses such as MSE and classification losses such as cross-entropy.

### 14. Why not use MSE for classification?

MSE is designed mainly for regression and reconstruction tasks. For classification, cross-entropy is more appropriate because it penalizes wrong class probabilities directly and works naturally with sigmoid or softmax outputs. MSE is more relevant to autoencoders, where the goal is to reconstruct the input.

### 15. How does backpropagation appear in your project?

Backpropagation is used to train the Torch MLP models. The network computes predictions in the forward pass, calculates a loss, and then propagates gradients backward to update weights. It is also used indirectly in adversarial attacks, because PGD uses gradients of the loss with respect to the input features rather than only with respect to the weights.

### 16. How is PGD related to gradient descent from class?

Gradient descent updates model weights to reduce loss. PGD uses a similar gradient idea, but it updates the input sample to increase the attacker's objective and cause evasion. In training, gradients improve the model. In adversarial attack, gradients are used against the model.

### 17. Why does the learning rate matter?

The learning rate controls the step size of updates. The course showed that a learning rate that is too small gives slow convergence, while one that is too large can overshoot or diverge. In our neural training, stable validation performance depends on controlled optimization, and adversarial fine-tuning also depends on careful perturbation step sizes.

### 18. Why use mini-batches?

Mini-batches balance the stability of batch gradient descent with the speed and noise benefits of stochastic gradient descent. The course presented mini-batch gradient descent as the industry standard. Our Torch models use mini-batch training so they can efficiently use the GPU while still generalizing better than full deterministic updates.

### 19. What is the generalization issue in this project?

Generalization means performance on unseen data, not only on training data. NSL-KDD has a clear train-test distribution shift, and KDDTest+ contains harder examples. Some models have very strong validation results but weaker test results. This is why the report emphasizes test metrics and limitations instead of only validation performance.

### 20. How is overfitting controlled?

Overfitting is controlled by validation monitoring, threshold selection on validation data, dropout or regularization in neural training where used, and by comparing multiple model families on the test split. For tree ensembles, overfitting is controlled through parameters such as tree depth, number of estimators, and leaf constraints. The final model is selected based on test behavior and robustness, not training accuracy.

### 21. How do L1 and L2 regularization relate to this project?

L1 and L2 regularization penalize model complexity. L1 promotes sparsity, while L2 discourages very large weights. Even when not every model explicitly uses L1 or L2, the idea is relevant: a good IDS should generalize and not memorize the training set. The same principle appears in tree depth control, neural regularization, and validation-based model selection.

### 22. What is the connection between dropout and IDS robustness?

Dropout randomly deactivates neurons during training so the model does not depend too strongly on one path. Conceptually, this helps generalization. In IDS, the same idea is important: if a detector relies too heavily on a few features, an attacker may target those features. Our final model addresses this more directly with SHAP-guided augmentation and ensembling.

### 23. How is your explainability work related to the CNN course's Grad-CAM example?

Grad-CAM shows which image regions influence a CNN decision. Our data is not visual, so we cannot use Grad-CAM directly. Instead, TreeSHAP and Integrated Gradients show which tabular features influence the IDS decision. The goal is the same: open the black box and identify what the model is using.

### 24. What is the difference between feature extraction in CNNs and feature importance in your project?

CNN feature extraction builds internal feature maps from local image patterns. Feature importance in our project explains which tabular inputs influence the decision. CNNs learn spatial filters such as edges and shapes, while our IDS explanations identify traffic and connection variables such as `flag_SF`, `same_srv_rate`, `dst_host_srv_count`, and error-rate features.

### 25. How does the CNN idea of local connectivity compare to your tabular model?

Local connectivity assumes nearby inputs are related, as neighboring pixels are in an image. In NSL-KDD tabular data, adjacent columns do not necessarily have local meaning. This is another reason CNN assumptions are weaker here. Tree ensembles and MLPs can learn relationships between arbitrary features without assuming spatial locality.

### 26. How is autoencoder anomaly detection related to IDS?

Autoencoders can be trained on normal traffic and detect anomalies using reconstruction error. If an input cannot be reconstructed well, it may be anomalous. This is directly relevant to IDS and was covered in the autoencoder course. In our project, we used supervised labels instead, but an autoencoder would be a strong future baseline for unsupervised anomaly detection.

### 27. Why did you not use an autoencoder as the final model?

The assignment and dataset provide labels, so supervised IDS models are more direct and easier to evaluate with precision, recall, F1, PR-AUC, and family recall. Autoencoders are useful when labels are missing or when the goal is anomaly detection from normal data only. They are a good extension, but the final project focuses on supervised explainable IDS and adversarial robustness.

### 28. What is the autoencoder bottleneck analogy in this project?

The autoencoder bottleneck forces the model to keep only essential information. In our project, feature attribution plays a related interpretability role: it identifies which features are essential for the IDS decision. However, we are not reconstructing inputs, so the bottleneck is only an analogy, not the actual model mechanism.

### 29. Could denoising autoencoders help against adversarial attacks?

Potentially yes. A denoising autoencoder learns to reconstruct clean inputs from corrupted inputs, so it could be used as a preprocessing defense. However, it would need careful validation because attackers may adapt to the denoising process. In our project, adversarial fine-tuning and robust tree augmentation were more direct defenses.

### 30. How are VAEs different from your model?

VAEs learn a probabilistic latent space using reconstruction loss and KL divergence. They are generative and can sample new data. Our IDS models are discriminative: they focus on classifying traffic as normal or attack. A VAE could be used for anomaly detection or synthetic data generation, but it is not the main method in our pipeline.

### 31. Are GANs related to adversarial attacks in this project?

They are related conceptually because both involve adversarial thinking. GANs train a generator and discriminator in a minimax game. Our adversarial attacks are not GANs, but they also involve an attacker trying to fool a detector. The difference is that PGD directly optimizes input perturbations using gradients, while GANs learn a generator distribution.

### 32. Could a GAN improve the dataset?

A GAN could generate synthetic attack samples, especially for rare classes such as R2L and U2R. This might help class imbalance, but GANs are difficult to train and can suffer from mode collapse. For a security project, synthetic data must also be realistic; otherwise, it can improve metrics without improving real IDS behavior.

### 33. How does the transformer concept of attention compare to SHAP?

Attention measures interactions between tokens inside a transformer using queries, keys, and values. SHAP measures feature contributions to a model prediction. Both can help interpret a model, but they are not the same. Attention is part of the model architecture; SHAP is a post-hoc explanation method applied after training.

### 34. What is multi-head attention, and why is it not central here?

Multi-head attention lets a transformer attend to different representation subspaces in parallel. It is important for language and long-range sequence tasks. Our input is a fixed tabular vector, not a long token sequence, so multi-head attention is not central to the final IDS design.

### 35. What is positional encoding, and why would it be questionable here?

Positional encoding gives a transformer information about token order because attention alone is permutation-insensitive. In NSL-KDD tabular features, column order is mostly artificial. Adding positional encoding would imply an order that may not have semantic meaning. This is another reason transformers are not the most natural choice here.

### 36. Why is model interpretability important for IDS?

An IDS alert must be explainable because analysts need to understand why a connection was flagged. If the model relies on meaningful features such as connection flags, service concentration, login behavior, and error rates, the alert is easier to trust. Interpretability also helps detect spurious behavior or dataset artifacts.

### 37. Why is interpretability also a security risk?

Interpretability can reveal the features that matter most to the model. If an attacker knows these features, they can attempt explanation-guided evasion. In our results, RF SHAP-guided evasion reaches 18.22%, and Torch IG-guided evasion reaches 15.97%. This proves that explanations are useful but also dual-use.

### 38. What does explanation stability mean using class vocabulary?

In class terms, stability is related to generalization of explanations. A stable explanation means the model's reasoning does not change randomly for similar inputs or resampled data. We measured this with local Jaccard, rank stability, bootstrap Jaccard, and bootstrap rank. The final ensemble has local Jaccard stability of 0.8453 and bootstrap Jaccard stability of 0.8873.

### 39. Why is stable explanation not always enough?

Stable explanations can still be wrong or incomplete if the model learned a dataset artifact. Stability says the explanation is consistent, not necessarily causally correct. That is why we combine explanation analysis with security reasoning and adversarial evaluation.

### 40. How do you justify adversarial training using class concepts?

Adversarial training is a form of data augmentation and regularization. During training, the model sees perturbed malicious examples and learns a decision boundary that is less fragile. This is similar to the class idea that a model should generalize beyond exact training points, but here the added examples are security-motivated perturbations.

### 41. Why did adversarial training not solve every PGD attack?

Because PGD is a strong white-box attack and high-epsilon perturbations can move samples far from their original region in feature space. The course discussed the tension between fitting, generalization, and optimization. Adversarial training improves robustness in some regions but cannot guarantee robustness everywhere, especially without certified defenses.

### 42. How do you explain the negative reduction at eps 0.03?

The negative reduction means the defended model had slightly higher evasion at the smallest mutable-feature perturbation budget: 14.05% instead of 11.70%. This is not hidden in the report. It shows that robustness is not monotonic across all budgets. The defense is stronger at eps 0.10 and eps 0.15, where reductions reach 32.03 and 42.03 percentage points.

### 43. What is the strongest result to defend?

The strongest result is the transfer-PGD defense of Adv+ExtraTrees. Evasion on the Torch surrogate is 37.29%, 63.99%, 91.24%, and 100.00%, but on the final ensemble it falls to 0.50%, 0.00%, 0.00%, and 0.00%. This shows that adversarial examples optimized on the neural model do not transfer effectively to the final heterogeneous ensemble.

### 44. Does 0.00% evasion prove the IDS is fully robust?

No. It proves only that no evasion was observed under the tested attack configuration. It is an empirical result, not a certified robustness proof. A stronger adaptive attacker or another dataset could produce different results. This distinction is important and should be stated clearly.

### 45. Why are tree ensembles strong for tabular IDS?

Tree ensembles are strong for tabular data because they capture nonlinear feature interactions, handle mixed feature types well after preprocessing, and often generalize strongly without requiring very deep neural architectures. ExtraTrees also introduces randomness in split selection, which can improve ensemble diversity.

### 46. How is an ensemble related to the course idea of generalization?

An ensemble combines multiple decision mechanisms so the final prediction is less dependent on one fragile model. In our project, the ensemble improves both clean performance and adversarial transfer robustness. This supports generalization because the deployed decision is not only the neural model's decision boundary.

### 47. Why is Security-OR not the default if it blocks transfer-PGD?

Security-OR is a stricter operating mode. It achieves 0.00% transfer-PGD evasion in the corrected presentation results, but its clean F1 is lower than Adv+ExtraTrees. In deployment terms, it is useful when false negatives are extremely costly, but the final default model should balance detection and alert quality.

### 48. What is the difference between validation and test results?

Validation results are used during development for threshold tuning and model selection. Test results are used for final evaluation. This distinction is important because using the test set for tuning would overfit the evaluation. The report uses KDDTest+ for final reported performance.

### 49. What is the main class concept behind your whole project?

The main class concept is that deep learning and machine learning systems learn representations and decision boundaries from data, but they must be evaluated for generalization, interpretability, and robustness. Our project applies those ideas to IDS by training models, explaining decisions, testing explanation stability, and evaluating adversarial evasion.

### 50. What should the examiner remember?

The examiner should remember that this is an explainable and security-aware IDS, not only a classifier. The final Adv+ExtraTrees ensemble reaches strong clean performance, explains its decisions with meaningful network features, shows stable explanations, and strongly reduces tested transfer-PGD evasion while clearly acknowledging limitations.

## If The Examiner Asks About The Course PDFs Themselves

The course files appear to be PowerPoint exports from INPT/Pr. Tarik Fissaa's deep learning course. Their metadata says they were created with Microsoft PowerPoint 2016. They cover deep learning fundamentals, CNNs, RNNs/LSTMs/GRUs, autoencoders/VAEs/GANs, and transformers/attention.

There is no reliable metadata evidence that a specific AI system such as ChatGPT, Claude, Gemini, Gamma, or Canva generated them. Some slides have a modern AI-assisted visual style, but that is not enough to identify the tool. The defensible answer is: the files were exported from PowerPoint and authored as INPT or INPT/FISSAA according to PDF metadata; any claim about which AI generated them would be speculation.
