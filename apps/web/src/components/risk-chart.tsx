"use client";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { RiskProfile } from "@/lib/types";
const colors=["#d9475b","#ee6a51","#d89a2b","#4f76ef","#8c9aab"];
export function RiskChart({risk}:{risk:RiskProfile}) {
  const data=Object.entries(risk).map(([name,value])=>({name,value})).filter(x=>x.value>0);
  if(!data.length)return <div className="empty" style={{padding:25}}>No findings yet</div>;
  const total=data.reduce((sum,item)=>sum+item.value,0);
  return <div className="risk-chart">
    <ResponsiveContainer width="100%" height="100%">
      <PieChart><Pie data={data} dataKey="value" nameKey="name" innerRadius={56} outerRadius={80} paddingAngle={3} isAnimationActive={false}>{data.map((_,i)=><Cell key={i} fill={colors[i]}/>)}</Pie><Tooltip contentStyle={{background:"var(--card)",border:"1px solid var(--border)",borderRadius:9,fontSize:11}}/></PieChart>
    </ResponsiveContainer>
    <div className="risk-total"><strong>{total}</strong><span>open</span></div>
  </div>;
}
