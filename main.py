import pandas as pd
import json
from openpyxl import load_workbook

farmer = pd.read_excel("farmer_sheet.xlsx")
bid_report = pd.read_excel("bid_data.xlsx")

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
        re.append({k1:k2})
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
        re.append({k1:k2})
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
        re.append({k1:k2})
    return re
seeds(farmer)

"""
this function main bar chart function
"""
def bar_chart(farmer):
    data = {
        "no_of_orders": {
            "pesticides":pesticides(farmer),
            "fertilizer":fertlizer(farmer),
            "seeds":seeds(farmer)
        },
    }
    return data

"""
this function gentrate status of company bidding status of each product
"""
def bid_status(bid_report):
    submitted=len(bid_report['company_name'])
    lost = bid_report.loc[bid_report.bid_status == 'lost', 'bid_status'].count()
    won = bid_report.loc[bid_report.bid_status == 'won', 'bid_status'].count()
    return {"bid_activity":{"submitted":str(submitted),"lost":str(lost),"won":str(won)}}
    
"""
this function top bid winner company names 
"""
def top_bid(bid_report):
    dt = bid_report.sort_values("amount", ascending=False)
    pcompany_name =[]
    scompany_name =[]
    fcompany_name =[]
    for k in json.loads(dt[['company_name','product_name','fpo_name']].to_json(orient='records')):
        if k['product_name'] == "pesticides":
            pcompany_name.append({k['company_name']:k['fpo_name']})
        if k['product_name'] == "seed":
            scompany_name.append({k['company_name']:k['fpo_name']})
        if k['product_name'] == "fertlizer":
            fcompany_name.append({k['company_name']:k['fpo_name']})
    return {"top_bids":{"pesticides":pcompany_name,"fertilizer":fcompany_name,"seeds":scompany_name}}


"""
this is main function of status cards
"""

def cards(bid_report,company_name):
    a = json.loads(bid_report.loc[bid_report['company_name'] == company_name][['bid_status','product_name']].to_json(orient='records'))
    for k in a:
        if k['product_name'] == "pesticides":
            pcompany_name=k['bid_status']
        else:
            pcompany_name=None
        if k['product_name'] == "seed":
            scompany_name=k['bid_status']
        else:
            scompany_name=None
        if k['product_name'] == "fertlizer":
            fcompany_name=k['bid_status']
        else:
            fcompany_name=None
    return {"bid_status":{"pesticides":pcompany_name,"fertilizer":fcompany_name,"seeds":scompany_name}}

def main(company_name):
    result={}
    a = farmer_count(farmer)
    b = bar_chart(farmer)
    c = bid_status(bid_report)
    d = top_bid(bid_report)
    e = cards(bid_report,company_name)
    result.update(a)
    result.update(b)
    result.update(c)
    result.update(d)
    result.update(e)
    return result


def login(username,pwd):
    dt = bid_report['company_name']
    for i in dt:
        if username ==i and pwd == "igcadmin@123":
            a = i
    return a

def insert_data(data):
    workbook_name = 'farmer_sheet.xlsx'
    wb = load_workbook(workbook_name)
    page = wb.active
    new_data = [data['company_id'],data['company_name'],data['bid_status'],data['product_name'],data['fpo_name'],data['warehouse_loc'],data['amount']]
    page.append(new_data)
    wb.save(filename=workbook_name)
login("company1","igcadmin@123")





