import hashlib
import json
from typing import Dict, Any, Optional, Tuple, Literal
from datetime import datetime

from pydantic import BaseModel

class PackageDocument(BaseModel):
    package_name:str
    sha:str
    updated_time:Optional[datetime]=None
    object:Dict[str,Any]
 

def calculate_full_response_sha(api_response: Dict[str, Any]) -> str:
    
    json_str = json.dumps(api_response, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    sha = hashlib.sha256(json_str.encode('utf-8')).hexdigest()
    
    return sha


def compare( data: Dict[str, Any], existing_sha: Optional[str],pkg_name: str, current_time: datetime)->Tuple[str, Dict[str, Any], Literal['insert', 'update', 'skip']]:
    new_sha = calculate_full_response_sha(data)
    data=data.copy()
    data['sha'] = new_sha
    data['_synced_at'] = current_time


    if existing_sha is None:
        data['_created_at']=current_time
        data['_updated_at']=current_time
        print(f"insert this packages - {pkg_name}")
        return new_sha,data,'insert'
    
    elif existing_sha !=new_sha:
        data['_updated_at']=current_time
        print(f"update this packages - {pkg_name}")
        return new_sha,data,'update'
    else:
        skip_data = {
            '_synced_at': current_time
        }
        print(f"skip this packages - {pkg_name}")
        return new_sha, skip_data, 'skip'

