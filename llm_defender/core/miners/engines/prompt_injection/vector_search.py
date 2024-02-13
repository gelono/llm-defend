import torch
import pinecone
import bittensor as bt
import transformers
from transformers import AutoModel, AutoTokenizer
from sklearn.ensemble import RandomForestClassifier
from datasets import load_dataset
import numpy as np
from llm_defender.base.engine import BaseEngine


class VectorEngine(BaseEngine):
    def __init__(self, name="engine:vector_search", prompt: str = None, reset_on_init=False):
        super().__init__(name=name)
        self.prompt = prompt
        self.collection_name = "prompt-injection-strings"
        self.reset_on_init = reset_on_init

        self.model_name = "July24/fmops"
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name, token='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')
        self.model = AutoModel.from_pretrained(self.model_name, token='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')

        self.pc = pinecone.Pinecone(api_key='0c73647e-5da7-4b8a-89ac-41dc3498ce9a')
        self.top_k = 1

        self.cosine_results = {'score': None}
        self.euclidean_results = {'score': None, 'data': None}
        self.dotproduct_results = {'score': None, 'data': None}
        self.model_rf=RandomForestClassifier(n_estimators=100, random_state=42)
        self.model_rf_trained = False

        self.train_model()

    def train_model(self):
        # Здесь вы можете добавить код для обучения модели
        url="July24/tets_vector_search"
        pred_data = load_dataset(url, token = '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')
        
        train_df=pred_data['train'].to_pandas()

        
        #column_to_drop=['label', 'text', 'dotproduct_score']
        column_to_drop=['label', 'text']
        X_train = train_df.drop(columns=column_to_drop)  # Features
        #X_test=test_df.drop(columns=column_to_drop)

        y_train = train_df['label']  # Target variable
        #y_test=test_df['label']
        # Предположим, что columns_to_convolve содержит имена трех фич для свертки

        columns_to_convolve = ['cosine_score', 'euclidean_score', 'dotproduct_score']

        kernel = np.array([0.5, 1,  0.5])
        
        #kernel = np.array([0.5, 1])

        # Применить свертку с ядром к выбранным фичам
        X_train['convolution'] = X_train[columns_to_convolve].apply(lambda x: np.convolve(x, kernel, mode='same').sum(), axis=1)
        #X_test['convolution'] = X_test[columns_to_convolve].apply(lambda x: np.convolve(x, kernel, mode='same').sum(), axis=1)

        self.model_rf.fit(X_train, y_train)
        self.model_trained = True

    def vectorize_text(self, text):
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, padding=True)

        with torch.no_grad():
            outputs = self.model(**inputs)

        embeddings = outputs.last_hidden_state.mean(dim=1).squeeze().numpy()

        return embeddings

    def perform_query(self, index_name):
        index = self.pc.Index(index_name)
        vector = self.vectorize_text(self.prompt).tolist()
        results_query = index.query(
            vector=vector,
            top_k=self.top_k,
            include_metadata=True,
        )
        results = []
        for match in results_query['matches']:
            score = match['score']
            text = match['metadata']['text']
            results.append({'score': score, 'text': text})

        
        return results

    def execute(self):
        try:
            self.cosine_results = self.perform_query(index_name='cosine')
            self.euclidean_results = self.perform_query(index_name='euclidean')
            self.dotproduct_results = self.perform_query(index_name='dotproduct')
            
            self._calculate_confidence()
	    self._populate_data()
        except pinecone.exceptions.PineconeException as e:
            raise Exception(f"Unable to query documents from collection: {e}") from e
        return True
      
    def _calculate_confidence(self):
      self.single_row_df = pd.DataFrame({
          'cosine_score': [self.cosine_results[0]['score']],
          'euclidean_score': [self.euclidean_results[0]['score']],
          'dotproduct_score': [self.dotproduct_results[0]['score']]
      })

      columns_to_convolve = ['cosine_score', 'euclidean_score', 'dotproduct_score']
      #columns_to_convolve = ['cosine_score', 'euclidean_score', ]
      kernel = np.array([0.5, 1, 0.5])

      # Применить свертку с ядром к выбранным фичам
      single_row_df['convolution'] = single_row_df[columns_to_convolve].apply(lambda x: np.convolve(x, kernel, mode='same').sum(), axis=1)
      self.convolve=single_row_df['convolution'][0]

      self.confidence = self.model_rf.predict(self.single_row_df)[0]

      #return self.pred

    def _populate_data(self):
        """
        Returns a dict instance that displays the outputs for the VectorEngine.

        Arguments:
            results:
                The results of executing the query using the collection from 
_calculate_confidenc                chromadb.PersistentClient

        Returns:
            A dict instance which contains a processed version of the inputted results.
            The flag 'outcome' will always be outputted, and the associated value is a 
            str instance which is either 'ResultsFound' or 'ResultsNotFound'. If the 'outcome'
            flag yields a 'ResultsFound' str, then the flags 'distances' and 'documents' will
            also be included in this dict.
        """
        if True:
            return {
                "outcome": "ResultsFound",
                "distances": [self.cosine_results, self.euclidean_results],
                "documents": f"{self.cosine_results[0]['text']}, {self.euclidean_results[0]['text']}",
            }
        return {"outcome": "ResultsNotFound"}

    def get_response(self) -> EngineResponse:
	    """Returns the outcome of the object.

	    This method returns the response from the engine in a correct
	    format so that it can be properly handled in the downstream
	    handlers.

	    Prior to calling this method, self.confidence and self.data
	    should be populated based on the return values from
	    calculate_confidence() and populate_data() methods.
	    _populate_data"""

       if not self.name or self.confidence is None or not self.output:
	   raise ValueError(
	            f"Instance attributes [self.name, self.confidence, self.data] cannot be empty. Values are: {[self.name, self.confidence, self.output]}")

`````` if not isinstance(self.name, str):
	   raise TypeError("Name must be a string")

`````` if not isinstance(self.confidence, float):	       
`````````` raise TypeError("Confidence must be a float")

```````if not isinstance(self.output, dict)
`````      raise TypeError("Output must be a dict")
````   response_dict = {
`````````` "name": self.name,
	   "confidence": self.confidence,
	   "data": self.output }
       return EngineResponse(**response_dict)


