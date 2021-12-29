import pandas as pd

farmer = pd.read_excel("farmer_sheet.xlsx")
farmer

"""
this function shows farmer count
"""
def farmer_count(farmer):
    return {"farmers_count":len(farmer['mobile_number'])}

"""
this function gentrate pesticides bar chart value
"""
def pesticides(farmer):
    mydict={}
    farmer = farmer.groupby(['fpo_name','month_pesticides'])['ltr_pesticides'].sum()
    result = []
    for k,v in farmer.to_dict().items():
        t = k
        t = t + (v,)
        result.append(t)
    a=[]
    b=[]
    c=[]
    for a1,b1,c1 in tuple(result):
        a.append(a1)
        b.append(b1)
        c.append(c1)
    data = {'fpo_name':a,
            'month':b,
           'values':c}
    new_df = pd.DataFrame(data)
    new_df = new_df.groupby('fpo_name')['values']
    re = []
    for k1,k2 in new_df.apply(list).to_dict().items():
        re.append({"label":k1,"value":k2})
    return re

"""
this function gentrate fertlizer bar chart value
"""
def fertlizer(farmer):
    mydict={}
    farmer = farmer.groupby(['fpo_name','month_fertlizer'])['kg_fertlizer'].sum()
    result = []
    for k,v in farmer.to_dict().items():
        t = k
        t = t + (v,)
        result.append(t)
    a=[]
    b=[]
    c=[]
    for a1,b1,c1 in tuple(result):
        a.append(a1)
        b.append(b1)
        c.append(c1)
    data = {'fpo_name':a,
            'month':b,
           'values':c}
    new_df = pd.DataFrame(data)
    new_df = new_df.groupby('fpo_name')['values']
    re = []
    for k1,k2 in new_df.apply(list).to_dict().items():
        re.append({"label":k1,"value":k2})
    return re

"""
this function gentrate seeds bar chart value
"""
def seeds(farmer):
    mydict={}
    farmer = farmer.groupby(['fpo_name','month_seeds'])['kg_seeds'].sum()
    result = []
    for k,v in farmer.to_dict().items():
        t = k
        t = t + (v,)
        result.append(t)
    a=[]
    b=[]
    c=[]
    for a1,b1,c1 in tuple(result):
        a.append(a1)
        b.append(b1)
        c.append(c1)
    data = {'fpo_name':a,
            'month':b,
           'values':c}
    new_df = pd.DataFrame(data)
    new_df = new_df.groupby('fpo_name')['values']
    re = []
    for k1,k2 in new_df.apply(list).to_dict().items():
        re.append({"label":k1,"value":k2})
    return re
seeds(farmer)

"""
this function main bar chart function
"""
def bar_chart():
    data = {"type":"bar",
    "dataset":
    {
        "pesticides":[{
        "dataset":pesticides(farmer)
    }],
          "seeds":[{
        "dataset":seeds(farmer)
    }],
          "fertlizer":[{
        "dataset":fertlizer(farmer)
    }]
    }}
    return data


bid_report = pd.read_excel("bid_data.xlsx")

"""
this function gentrate status of company bidding status of each product
"""
def bid_status(bid_report):
    submitted=len(bid_report['company_name'])
    lost = bid_report.loc[bid_report.bid_status == 'lost', 'bid_status'].count()
    won = bid_report.loc[bid_report.bid_status == 'won', 'bid_status'].count()
    return {"type":"pie","dataset":[submitted,lost,won]}
import json

"""
this function top bid winner company names 
"""
def top_bid(bid_report):
    dt = bid_report.sort_values("amount", ascending=False)
    return {"type":"top_bid","dataset":json.loads(dt[['company_name','product_name','fpo_name','amount']].to_json(orient='records'))}
"""
this is main function of status cards
"""
def cards(bid_report,company_name):
    ds = []
    a = json.loads(bid_report.loc[bid_report['company_name'] == company_name][['bid_status','product_name']].to_json(orient='records'))
    return {"type":"top_bid","dataset":a}

cards(bid_report,"company1")




