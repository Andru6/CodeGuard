import json
import os
import logging

logger = logging.getLogger(__name__)

class RAGEngine:
    def __init__(self, knowledge_path=None):
        if knowledge_path is None:
            # Default to the cwe_mitre.json in resources
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            knowledge_path = os.path.join(base_dir, 'backend', 'resources', 'cwe_mitre.json')
        
        self.knowledge_path = knowledge_path
        self.knowledge = []
        self._load_knowledge()

    def _load_knowledge(self):
        try:
            if os.path.exists(self.knowledge_path):
                with open(self.knowledge_path, 'r') as f:
                    self.knowledge = json.load(f)
                logger.info(f"RAG Engine loaded {len(self.knowledge)} knowledge items.")
            else:
                logger.warning(f"RAG Knowledge path not found: {self.knowledge_path}")
        except Exception as e:
            logger.error(f"Failed to load RAG knowledge: {str(e)}")

    def find_relevant_context(self, code_snippet, category=None, file_path=None):
        """
        Retrieves relevant CWE context based on the vulnerability category or keywords in code.
        """
        relevant = []
        snippet_lower = str(code_snippet).lower()
        
        # 0. Language Detection
        ext = os.path.splitext(file_path)[1].lower() if file_path else None
        is_python = ext in ['.py']
        is_node = ext in ['.js', '.jsx', '.ts', '.tsx']
        
        # 1. Match by category (High Precision)
        if category:
            cat_lower = str(category).lower()
            for item in self.knowledge:
                if cat_lower in item['name'].lower() or cat_lower in item['cwe_id'].lower():
                    relevant.append(item)
        
        # 2. Keyword & Indicator Match (Broad Sweep)
        if not relevant:
            python_keywords = ["flask", "django", "app.route", "render_template", "pickle", "os.system", "subprocess", "sqlalchemy", "db.session"]
            node_keywords = ["express", "res.send", "res.write", "mongoose", "sequelize", "knex", "passport", "cookie", "session"]
            common_keywords = ["sql", "select", "insert", "delete", "script", "eval", "exec", "system", "shell", "cmd", "upload", "file", "path", "traversal", "auth", "token", "jwt", "crypto", "hash", "md5"]
            
            keywords = common_keywords
            if is_python: keywords += python_keywords
            if is_node: keywords += node_keywords
            
            for item in self.knowledge:
                # Check keywords in name
                for kw in keywords:
                    if kw in snippet_lower and kw in item['name'].lower():
                        relevant.append(item)
                        break
                # Check specific indicators
                if item not in relevant and 'indicators' in item:
                    for ind in item['indicators']:
                        if ind.lower() in snippet_lower:
                            relevant.append(item)
                            break
        
        return relevant[:3]

    def get_minimal_context(self, code_snippet, category=None, file_path=None):
        """
        Retrieves a token-efficient version of relevant CWE context.
        Only includes ID, Name, and critical indicators.
        """
        items = self.find_relevant_context(code_snippet, category, file_path)
        if not items: return ""
        
        context_lines = []
        for it in items:
            indicators = ", ".join(it.get('indicators', []))[:100]
            context_lines.append(f"CWE-{it['cwe_id']} ({it['name']}) -> Indicators: [{indicators}]")
            
        return "\n".join(context_lines)

    def augment_prompt(self, base_prompt, code_snippet, category=None, file_path=None, minimal=False):
        """
        Injects knowledge base context into the LLM prompt.
        Set 'minimal=True' for Claude-level token efficiency.
        """
        if minimal:
            context_str = self.get_minimal_context(code_snippet, category, file_path)
        else:
            context_items = self.find_relevant_context(code_snippet, category, file_path)
            context_str = "\n".join([
                f"- {item['cwe_id']} ({item['name']}): {item['description']}\n  SEVERITY: {item.get('severity', 'Medium')}\n  REMEDIATION: {item['remediation']}" 
                for item in context_items
            ]) if context_items else ""

        if not context_str:
            return base_prompt

        augmented = f"""
{base_prompt}

### SECURITY KNOWLEDGE BASE (CWE REFERENCE):
{context_str}

---
        """
        return augmented.strip()
